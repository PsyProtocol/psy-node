//https://grok.com/c/91b57cd8-4b65-46f0-8d95-5104be519eca
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use bincode::{deserialize, serialize};
use dashmap::DashMap;
use parking_lot::RwLock;
use parth_core::crypto::hash::tag_tree::TagTreeNodePreimage;
use parth_core::{
    crypto::hash::{
        tag_tree::{TagTreeMerkleProof, TagTreeProofNode},
        traits::{MerkleHasher, MerkleZeroHasher},
    },
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

use serde::{de::DeserializeOwned, Serialize};

pub type TableIdentifier = String;

#[derive(Clone)]
pub struct InMemoryCoreStore<Hash, Hasher> {
    bidir_maps: DashMap<TableIdentifier, Arc<(RwLock<BTreeMap<Vec<u8>, Vec<u8>>>, RwLock<BTreeMap<Vec<u8>, Vec<u8>>>)>>,
    bidir_u64_u128_maps: DashMap<TableIdentifier, Arc<(RwLock<BTreeMap<u64, u128>>, RwLock<BTreeMap<u128, u64>>)>>,

    u64_tables: DashMap<TableIdentifier, DashMap<u64, RwLock<u64>>>,
    single_id_checkpointed: DashMap<TableIdentifier, DashMap<u64, RwLock<BTreeMap<Reverse<u64>, Vec<u8>>>>>,
    double_id_checkpointed: DashMap<TableIdentifier, DashMap<QDoubleIdKey, RwLock<BTreeMap<Reverse<u64>, Vec<u8>>>>>,
    kiv_tables: DashMap<TableIdentifier, DashMap<u64, RwLock<Vec<u8>>>>,
    single_id_merkle: DashMap<TableIdentifier, DashMap<u64, RwLock<HashMap<SimpleMerkleNodeKey, BTreeMap<Reverse<u64>, Hash>>>>>,
    double_id_merkle: DashMap<TableIdentifier, DashMap<QDoubleIdKey, RwLock<HashMap<SimpleMerkleNodeKey, BTreeMap<Reverse<u64>, Hash>>>>>,
    zero_id_merkle: DashMap<TableIdentifier, RwLock<HashMap<SimpleMerkleNodeKey, BTreeMap<Reverse<u64>, Hash>>>>,
    tag_trees: DashMap<TableIdentifier, DashMap<u64, RwLock<HashMap<SimpleMerkleNodeKey, (Hash, Hash)>>>>,
    _phantom: PhantomData<(Hash, Hasher)>,
}

impl<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>> InMemoryCoreStore<Hash, Hasher> {
    pub fn new() -> Self {
        Self {
            bidir_maps: DashMap::new(),
            bidir_u64_u128_maps: DashMap::new(),
            u64_tables: DashMap::new(),
            single_id_checkpointed: DashMap::new(),
            double_id_checkpointed: DashMap::new(),
            kiv_tables: DashMap::new(),
            single_id_merkle: DashMap::new(),
            double_id_merkle: DashMap::new(),
            zero_id_merkle: DashMap::new(),
            tag_trees: DashMap::new(),
            _phantom: PhantomData,
        }
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseBidirectionalMappingReader<TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_one_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k1: &K1,
    ) -> anyhow::Result<Option<K2>> {
        if let Some(t) = self.bidir_maps.get(table) {
            let guard = t.0.read();
            if let Some(bytes) = guard.get(&k1.to_bytes()?) {
                return K2::from_bytes(bytes).map(Some);
            }
        }
        Ok(None)
    }

    async fn db_select_one_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k2: &K2,
    ) -> anyhow::Result<Option<K1>> {
        if let Some(t) = self.bidir_maps.get(table) {
            let guard = t.1.read();
            if let Some(bytes) = guard.get(&k2.to_bytes()?) {
                return K1::from_bytes(bytes).map(Some);
            }
        }
        Ok(None)
    }

    async fn db_select_many_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k1s: &[K1],
    ) -> anyhow::Result<Vec<Option<K2>>> {
        let mut res = Vec::with_capacity(k1s.len());
        if let Some(t) = self.bidir_maps.get(table) {
            let guard = t.0.read();
            for k1 in k1s {
                let k1_bytes = k1.to_bytes()?;
                res.push(guard.get(&k1_bytes).and_then(|b| K2::from_bytes(b).ok()));
            }
        } else {
            res.resize(k1s.len(), None);
        }
        Ok(res)
    }

    async fn db_select_many_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k2s: &[K2],
    ) -> anyhow::Result<Vec<Option<K1>>> {
        let mut res = Vec::with_capacity(k2s.len());
        if let Some(t) = self.bidir_maps.get(table) {
            let guard = t.1.read();
            for k2 in k2s {
                let k2_bytes = k2.to_bytes()?;
                res.push(guard.get(&k2_bytes).and_then(|b| K1::from_bytes(b).ok()));
            }
        } else {
            res.resize(k2s.len(), None);
        }
        Ok(res)
    }

    async fn db_select_many_pairs_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k1s: &[K1],
    ) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        let mut res = Vec::new();
        if let Some(t) = self.bidir_maps.get(table) {
            let guard = t.0.read();
            for k1 in k1s {
                if let Some(k2_bytes) = guard.get(&k1.to_bytes()?) {
                    if let Ok(k2) = K2::from_bytes(k2_bytes) {
                        res.push(BiDirectionalMappingRow { k1: k1.clone(), k2 });
                    }
                }
            }
        }
        Ok(res)
    }

    async fn db_select_many_pairs_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k2s: &[K2],
    ) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        let mut res = Vec::new();
        if let Some(t) = self.bidir_maps.get(table) {
            let guard = t.1.read();
            for k2 in k2s {
                if let Some(k1_bytes) = guard.get(&k2.to_bytes()?) {
                    if let Ok(k1) = K1::from_bytes(k1_bytes) {
                        res.push(BiDirectionalMappingRow { k1, k2: k2.clone() });
                    }
                }
            }
        }
        Ok(res)
    }

    async fn db_select_all_pairs_from_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        start_k1: Option<K1>,
        max_count: usize,
    ) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        let mut res = Vec::new();
        if let Some(t) = self.bidir_maps.get(table) {
            let guard = t.0.read();
            let start = start_k1.as_ref().map(|k| k.to_bytes()).transpose()?;
            let iter = if let Some(start) = start {
                guard.range(start..)
            } else {
                guard.range(..)
            };
            for (k1_b, k2_b) in iter.take(max_count) {
                let k1 = K1::from_bytes(k1_b)?;
                let k2 = K2::from_bytes(k2_b)?;
                res.push(BiDirectionalMappingRow { k1, k2 });
            }
        }
        Ok(res)
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseBidirectionalMappingWriter<TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_pair_ref<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k1: &K1,
        k2: &K2,
    ) -> anyhow::Result<()> {
        let k1_bytes = k1.to_bytes()?;
        let k2_bytes = k2.to_bytes()?;
        let t = self.bidir_maps.entry(table.clone()).or_insert_with(|| Arc::new((RwLock::new(BTreeMap::new()), RwLock::new(BTreeMap::new()))));
        let mut forward = t.0.write();
        let mut reverse = t.1.write();
        forward.insert(k1_bytes.clone(), k2_bytes.clone());
        reverse.insert(k2_bytes, k1_bytes);
        Ok(())
    }

    async fn db_insert_pair<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k1: K1,
        k2: K2,
    ) -> anyhow::Result<()> {
        self.db_insert_pair_ref(table, &k1, &k2).await
    }

    async fn db_insert_pairs<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        keys: &[BiDirectionalMappingRow<K1, K2>],
    ) -> anyhow::Result<()> {
        let t = self.bidir_maps.entry(table.clone()).or_insert_with(|| Arc::new((RwLock::new(BTreeMap::new()), RwLock::new(BTreeMap::new()))));
        let mut forward = t.0.write();
        let mut reverse = t.1.write();
        for row in keys {
            let k1_bytes = row.k1.to_bytes()?;
            let k2_bytes = row.k2.to_bytes()?;
            forward.insert(k1_bytes.clone(), k2_bytes.clone());
            reverse.insert(k2_bytes, k1_bytes);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseBidirectionalU64U128MappingReader<TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_one_u128_value_by_u64(&self, table: &TableIdentifier, key: u64) -> anyhow::Result<Option<u128>> {
        if let Some(t) = self.bidir_u64_u128_maps.get(table) {
            let guard = t.0.read();
            Ok(guard.get(&key).cloned())
        } else {
            Ok(None)
        }
    }

    async fn db_select_one_u64_key_by_u128(&self, table: &TableIdentifier, value: u128) -> anyhow::Result<Option<u64>> {
        if let Some(t) = self.bidir_u64_u128_maps.get(table) {
            let guard = t.1.read();
            Ok(guard.get(&value).cloned())
        } else {
            Ok(None)
        }
    }

    async fn db_select_many_u128_values_by_u64s(&self, table: &TableIdentifier, keys: &[u64]) -> anyhow::Result<Vec<Option<u128>>> {
        let mut res = Vec::with_capacity(keys.len());
        if let Some(t) = self.bidir_u64_u128_maps.get(table) {
            let guard = t.0.read();
            for k in keys {
                res.push(guard.get(k).cloned());
            }
        } else {
            res.resize(keys.len(), None);
        }
        Ok(res)
    }

    async fn db_select_many_u64_keys_by_u128s(&self, table: &TableIdentifier, values: &[u128]) -> anyhow::Result<Vec<Option<u64>>> {
        let mut res = Vec::with_capacity(values.len());
        if let Some(t) = self.bidir_u64_u128_maps.get(table) {
            let guard = t.1.read();
            for v in values {
                res.push(guard.get(v).cloned());
            }
        } else {
            res.resize(values.len(), None);
        }
        Ok(res)
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseBidirectionalU64U128MappingWriter<TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_u64_u128_mapping_pair(&self, table: &TableIdentifier, k1: u64, k2: u128) -> anyhow::Result<()> {
        let t = self.bidir_u64_u128_maps.entry(table.clone()).or_insert_with(|| Arc::new((RwLock::new(BTreeMap::new()), RwLock::new(BTreeMap::new()))));
        let mut forward = t.0.write();
        let mut reverse = t.1.write();
        forward.insert(k1, k2);
        reverse.insert(k2, k1);
        Ok(())
    }

    async fn db_insert_u64_u128_mapping_pairs(&self, table: &TableIdentifier, keys: &[BiDirectionalMappingRow<u64, u128>]) -> anyhow::Result<()> {
        let t = self.bidir_u64_u128_maps.entry(table.clone()).or_insert_with(|| Arc::new((RwLock::new(BTreeMap::new()), RwLock::new(BTreeMap::new()))));
        let mut forward = t.0.write();
        let mut reverse = t.1.write();
        for row in keys {
            forward.insert(row.k1, row.k2);
            reverse.insert(row.k2, row.k1);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseU64Reader<TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_u64_value(&self, table: &TableIdentifier, obj_id: u64) -> anyhow::Result<Option<u64>> {
        if let Some(t) = self.u64_tables.get(table) {
            Ok(t.get(&obj_id).map(|r| *r.read()))
        } else {
            Ok(None)
        }
    }

    async fn db_select_u64_values(&self, table: &TableIdentifier, obj_ids: &[u64]) -> anyhow::Result<Vec<Option<u64>>> {
        let mut res = Vec::with_capacity(obj_ids.len());
        if let Some(t) = self.u64_tables.get(table) {
            for id in obj_ids {
                res.push(t.get(id).map(|r| *r.read()));
            }
        } else {
            res.resize(obj_ids.len(), None);
        }
        Ok(res)
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseU64Writer<TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_inc_counter(&self, table: &TableIdentifier, obj_id: u64, amount: i64) -> anyhow::Result<u64> {
        let t = self.u64_tables.entry(table.clone()).or_default();
        let entry = t.entry(obj_id).or_insert_with(|| RwLock::new(0));
        let mut guard = entry.write();
        if amount > 0 {
            *guard += amount as u64;
        } else if amount < 0 {
            let abs = (-amount) as u64;
            if *guard >= abs {
                *guard -= abs;
            } else {
                *guard = 0;
            }
        }
        Ok(*guard)
    }

    async fn db_set_u64_value(&self, table: &TableIdentifier, obj_id: u64, value: u64) -> anyhow::Result<()> {
        let t = self.u64_tables.entry(table.clone()).or_default();
        let entry = t.entry(obj_id).or_insert_with(|| RwLock::new(0));
        let mut guard = entry.write();
        *guard = value;
        Ok(())
    }

    async fn db_set_many_u64_values(&self, table: &TableIdentifier, rows: &[QPDPair<u64, u64>]) -> anyhow::Result<()> {
        let t = self.u64_tables.entry(table.clone()).or_default();
        for row in rows {
            let entry = t.entry(row.key).or_insert_with(|| RwLock::new(0));
            let mut guard = entry.write();
            *guard = row.value;
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseSingleIdCheckpointedReader<TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_one_single_checkpointed_object_value<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<V>> {
        if let Some(t) = self.single_id_checkpointed.get(table) {
            if let Some(inner) = t.get(&obj_id) {
                let guard = inner.read();
                if let Some((_, bytes)) = guard.range(Reverse(max_checkpoint_id)..).next() {
                    return deserialize(bytes).map(Some).map_err(Into::into);
                }
            }
        }
        Ok(None)
    }

    async fn db_select_one_single_checkpointed_object_value_and_ids<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<QDatabaseSingleIdTableRow<V>>> {
        if let Some(t) = self.single_id_checkpointed.get(table) {
            if let Some(inner) = t.get(&obj_id) {
                let guard = inner.read();
                if let Some((Reverse(cp), bytes)) = guard.range(Reverse(max_checkpoint_id)..).next() {
                    let value = deserialize(bytes)?;
                    return Ok(Some(QDatabaseSingleIdTableRow { obj_id, checkpoint_id: *cp, value }));
                }
            }
        }
        Ok(None)
    }

    async fn db_select_one_single_checkpointed_object_value_and_ids_t<
        V: CoreDatabaseValueDeserialize,
        R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<R>> {
        if let Some(t) = self.single_id_checkpointed.get(table) {
            if let Some(inner) = t.get(&obj_id) {
                let guard = inner.read();
                if let Some((Reverse(cp), bytes)) = guard.range(Reverse(max_checkpoint_id)..).next() {
                    let value = deserialize(bytes)?;
                    return Ok(Some(R::create_from_single_row(obj_id, *cp, value)));
                }
            }
        }
        Ok(None)
    }

    async fn db_select_all_single_checkpointed_object<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &TableIdentifier,
    ) -> anyhow::Result<Vec<QDatabaseSingleIdTableRow<V>>> {
        let mut res = Vec::new();
        if let Some(t) = self.single_id_checkpointed.get(table) {
            for entry in t.iter() {
                let obj_id = *entry.key();
                let guard = entry.value().read();
                for (Reverse(cp), bytes) in guard.iter() {
                    let value = deserialize(bytes)?;
                    res.push(QDatabaseSingleIdTableRow { obj_id, checkpoint_id: *cp, value });
                }
            }
        }
        Ok(res)
    }

    async fn db_select_many_single_checkpointed_object_values<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &TableIdentifier,
        obj_ids: &[u64],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<Option<V>>> {
        let mut res = Vec::with_capacity(obj_ids.len());
        if let Some(t) = self.single_id_checkpointed.get(table) {
            for id in obj_ids {
                if let Some(inner) = t.get(id) {
                    let guard = inner.read();
                    if let Some((_, bytes)) = guard.range(Reverse(max_checkpoint_id)..).next() {
                        res.push(Some(deserialize(bytes)?));
                        continue;
                    }
                }
                res.push(None);
            }
        } else {
            res.resize(obj_ids.len(), None);
        }
        Ok(res)
    }

    async fn db_select_many_single_checkpointed_object_keys_and_values<
        V: CoreDatabaseValueDeserialize,
        R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &TableIdentifier,
        obj_ids: &[u64],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<R>> {
        let mut res = Vec::new();
        if let Some(t) = self.single_id_checkpointed.get(table) {
            for id in obj_ids {
                if let Some(inner) = t.get(id) {
                    let guard = inner.read();
                    if let Some((Reverse(cp), bytes)) = guard.range(Reverse(max_checkpoint_id)..).next() {
                        let value = deserialize(bytes)?;
                        res.push(R::create_from_single_row(*id, *cp, value));
                    }
                }
            }
        }
        Ok(res)
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseSingleIdCheckpointedWriter<TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_one_single_checkpointed_object<V: Serialize + Send + Sync>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> anyhow::Result<()> {
        let bytes = serialize(value)?;
        let t = self.single_id_checkpointed.entry(table.clone()).or_default();
        let inner = t.entry(obj_id).or_insert_with(|| RwLock::new(BTreeMap::new()));
        let mut guard = inner.write();
        guard.insert(Reverse(checkpoint_id), bytes);
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_object_rows<V: Serialize + Send + Sync>(
        &self,
        table: &TableIdentifier,
        rows: &[QDatabaseSingleIdTableRow<V>],
    ) -> anyhow::Result<()> {
        let t = self.single_id_checkpointed.entry(table.clone()).or_default();
        for row in rows {
            let bytes = serialize(&row.value)?;
            let inner = t.entry(row.obj_id).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut guard = inner.write();
            guard.insert(Reverse(row.checkpoint_id), bytes);
        }
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_object_rows_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseSingleIdTableRowLike<V> + Send + Sync,
    >(
        &self,
        table: &TableIdentifier,
        rows: &[R],
    ) -> anyhow::Result<()> {
        let t = self.single_id_checkpointed.entry(table.clone()).or_default();
        for row in rows {
            let bytes = serialize(row.get_row_value_ref())?;
            let inner = t.entry(row.get_row_obj_id()).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut guard = inner.write();
            guard.insert(Reverse(row.get_row_checkpoint_id()), bytes);
        }
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_objects_at_checkpoint<V: Serialize + Send + Sync>(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        rows: &[QDatabaseSingleIdTableRowNoCheckpointId<V>],
    ) -> anyhow::Result<()> {
        let t = self.single_id_checkpointed.entry(table.clone()).or_default();
        for row in rows {
            let bytes = serialize(&row.value)?;
            let inner = t.entry(row.obj_id).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut guard = inner.write();
            guard.insert(Reverse(checkpoint_id), bytes);
        }
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseSingleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        rows: &[R],
    ) -> anyhow::Result<()> {
        let t = self.single_id_checkpointed.entry(table.clone()).or_default();
        for row in rows {
            let bytes = serialize(row.get_row_value_ref())?;
            let inner = t.entry(row.get_row_obj_id()).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut guard = inner.write();
            guard.insert(Reverse(checkpoint_id), bytes);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseDoubleIdCheckpointedReader<TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_one_double_checkpointed_object_value<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<V>> {
        let key = QDoubleIdKey { obj_id, secondary_id };
        if let Some(t) = self.double_id_checkpointed.get(table) {
            if let Some(inner) = t.get(&key) {
                let guard = inner.read();
                if let Some((_, bytes)) = guard.range(Reverse(max_checkpoint_id)..).next() {
                    return deserialize(bytes).map(Some).map_err(Into::into);
                }
            }
        }
        Ok(None)
    }

    async fn db_select_one_double_checkpointed_object_value_and_ids<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<QDatabaseDoubleIdTableRow<V>>> {
        let key = QDoubleIdKey { obj_id, secondary_id };
        if let Some(t) = self.double_id_checkpointed.get(table) {
            if let Some(inner) = t.get(&key) {
                let guard = inner.read();
                if let Some((Reverse(cp), bytes)) = guard.range(Reverse(max_checkpoint_id)..).next() {
                    let value = deserialize(bytes)?;
                    return Ok(Some(QDatabaseDoubleIdTableRow { obj_id, secondary_id, checkpoint_id: *cp, value }));
                }
            }
        }
        Ok(None)
    }

    async fn db_select_one_double_checkpointed_object_value_and_ids_t<
        V: CoreDatabaseValueDeserialize,
        R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<R>> {
        let key = QDoubleIdKey { obj_id, secondary_id };
        if let Some(t) = self.double_id_checkpointed.get(table) {
            if let Some(inner) = t.get(&key) {
                let guard = inner.read();
                if let Some((Reverse(cp), bytes)) = guard.range(Reverse(max_checkpoint_id)..).next() {
                    let value = deserialize(bytes)?;
                    return Ok(Some(R::create_from_double_row(obj_id, secondary_id, *cp, value)));
                }
            }
        }
        Ok(None)
    }

    async fn db_select_all_double_checkpointed_object<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &TableIdentifier,
    ) -> anyhow::Result<Vec<QDatabaseDoubleIdTableRow<V>>> {
        let mut res = Vec::new();
        if let Some(t) = self.double_id_checkpointed.get(table) {
            for entry in t.iter() {
                let key = entry.key();
                let obj_id = key.obj_id;
                let secondary_id = key.secondary_id;
                let guard = entry.value().read();
                for (Reverse(cp), bytes) in guard.iter() {
                    let value = deserialize(bytes)?;
                    res.push(QDatabaseDoubleIdTableRow { obj_id, secondary_id, checkpoint_id: *cp, value });
                }
            }
        }
        Ok(res)
    }

    async fn db_select_many_double_checkpointed_object_values<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &TableIdentifier,
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<Option<V>>> {
        let mut res = Vec::with_capacity(obj_ids.len());
        if let Some(t) = self.double_id_checkpointed.get(table) {
            for key in obj_ids {
                if let Some(inner) = t.get(key) {
                    let guard = inner.read();
                    if let Some((_, bytes)) = guard.range(Reverse(max_checkpoint_id)..).next() {
                        res.push(Some(deserialize(bytes)?));
                        continue;
                    }
                }
                res.push(None);
            }
        } else {
            res.resize(obj_ids.len(), None);
        }
        Ok(res)
    }

    async fn db_select_many_double_checkpointed_object_keys_and_values<
        V: CoreDatabaseValueDeserialize,
        R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &TableIdentifier,
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<R>> {
        let mut res = Vec::new();
        if let Some(t) = self.double_id_checkpointed.get(table) {
            for key in obj_ids {
                if let Some(inner) = t.get(key) {
                    let guard = inner.read();
                    if let Some((Reverse(cp), bytes)) = guard.range(Reverse(max_checkpoint_id)..).next() {
                        let value = deserialize(bytes)?;
                        res.push(R::create_from_double_row(key.obj_id, key.secondary_id, *cp, value));
                    }
                }
            }
        }
        Ok(res)
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseDoubleIdCheckpointedWriter<TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_one_double_checkpointed_object<V: Serialize + Send + Sync>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        secondary_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> anyhow::Result<()> {
        let bytes = serialize(value)?;
        let key = QDoubleIdKey { obj_id, secondary_id };
        let t = self.double_id_checkpointed.entry(table.clone()).or_default();
        let inner = t.entry(key).or_insert_with(|| RwLock::new(BTreeMap::new()));
        let mut guard = inner.write();
        guard.insert(Reverse(checkpoint_id), bytes);
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_object_rows<V: Serialize + Send + Sync>(
        &self,
        table: &TableIdentifier,
        rows: &[QDatabaseDoubleIdTableRow<V>],
    ) -> anyhow::Result<()> {
        let t = self.double_id_checkpointed.entry(table.clone()).or_default();
        for row in rows {
            let bytes = serialize(&row.value)?;
            let key = QDoubleIdKey { obj_id: row.obj_id, secondary_id: row.secondary_id };
            let inner = t.entry(key).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut guard = inner.write();
            guard.insert(Reverse(row.checkpoint_id), bytes);
        }
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_object_rows_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseDoubleIdTableRowLike<V> + Send + Sync,
    >(
        &self,
        table: &TableIdentifier,
        rows: &[R],
    ) -> anyhow::Result<()> {
        let t = self.double_id_checkpointed.entry(table.clone()).or_default();
        for row in rows {
            let bytes = serialize(row.get_row_value_ref())?;
            let key = QDoubleIdKey { obj_id: row.get_row_obj_id(), secondary_id: row.get_row_secondary_id() };
            let inner = t.entry(key).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut guard = inner.write();
            guard.insert(Reverse(row.get_row_checkpoint_id()), bytes);
        }
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_objects_at_checkpoint<V: Serialize + Send + Sync>(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        rows: &[QDatabaseDoubleIdTableRowNoCheckpointId<V>],
    ) -> anyhow::Result<()> {
        let t = self.double_id_checkpointed.entry(table.clone()).or_default();
        for row in rows {
            let bytes = serialize(&row.value)?;
            let key = QDoubleIdKey { obj_id: row.obj_id, secondary_id: row.secondary_id };
            let inner = t.entry(key).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut guard = inner.write();
            guard.insert(Reverse(checkpoint_id), bytes);
        }
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_objects_at_checkpoint_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseDoubleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        rows: &[R],
    ) -> anyhow::Result<()> {
        let t = self.double_id_checkpointed.entry(table.clone()).or_default();
        for row in rows {
            let bytes = serialize(row.get_row_value_ref())?;
            let key = QDoubleIdKey { obj_id: row.get_row_obj_id(), secondary_id: row.get_row_secondary_id() };
            let inner = t.entry(key).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut guard = inner.write();
            guard.insert(Reverse(checkpoint_id), bytes);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseKivReader<TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_one_kiv_value<V: CoreDatabaseValueDeserialize>(&self, table: &TableIdentifier, obj_id: u64) -> anyhow::Result<Option<V>> {
        if let Some(t) = self.kiv_tables.get(table) {
            if let Some(inner) = t.get(&obj_id) {
                let guard = inner.read();
                return deserialize(&*guard).map(Some).map_err(Into::into);
            }
        }
        Ok(None)
    }

    async fn db_select_one_kiv_value_and_ids<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
    ) -> anyhow::Result<Option<QDatabaseKeyIdValueTableRow<V>>> {
        if let Some(t) = self.kiv_tables.get(table) {
            if let Some(inner) = t.get(&obj_id) {
                let guard = inner.read();
                let value = deserialize(&*guard)?;
                return Ok(Some(QDatabaseKeyIdValueTableRow { obj_id, value }));
            }
        }
        Ok(None)
    }

    async fn db_select_one_kiv_value_and_ids_t<V: CoreDatabaseValueDeserialize, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
    ) -> anyhow::Result<Option<R>> {
        if let Some(t) = self.kiv_tables.get(table) {
            if let Some(inner) = t.get(&obj_id) {
                let guard = inner.read();
                let value = deserialize(&*guard)?;
                return Ok(Some(R::create_from_key_id_value_row(obj_id, value)));
            }
        }
        Ok(None)
    }

    async fn db_select_all_kiv<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &TableIdentifier,
    ) -> anyhow::Result<Vec<QDatabaseKeyIdValueTableRow<V>>> {
        let mut res = Vec::new();
        if let Some(t) = self.kiv_tables.get(table) {
            for entry in t.iter() {
                let obj_id = *entry.key();
                let guard = entry.value().read();
                let value = deserialize(&*guard)?;
                res.push(QDatabaseKeyIdValueTableRow { obj_id, value });
            }
        }
        Ok(res)
    }

    async fn db_select_many_kiv_values<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &TableIdentifier,
        obj_ids: &[u64],
    ) -> anyhow::Result<Vec<Option<V>>> {
        let mut res = Vec::with_capacity(obj_ids.len());
        if let Some(t) = self.kiv_tables.get(table) {
            for id in obj_ids {
                if let Some(inner) = t.get(id) {
                    let guard = inner.read();
                    res.push(Some(deserialize(&*guard)?));
                } else {
                    res.push(None);
                }
            }
        } else {
            res.resize(obj_ids.len(), None);
        }
        Ok(res)
    }

    async fn db_select_many_kiv_keys_and_values<V: CoreDatabaseValueDeserialize, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(
        &self,
        table: &TableIdentifier,
        obj_ids: &[u64],
    ) -> anyhow::Result<Vec<R>> {
        let mut res = Vec::new();
        if let Some(t) = self.kiv_tables.get(table) {
            for id in obj_ids {
                if let Some(inner) = t.get(id) {
                    let guard = inner.read();
                    let value = deserialize(&*guard)?;
                    res.push(R::create_from_key_id_value_row(*id, value));
                }
            }
        }
        Ok(res)
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseKivWriter<TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_one_kiv<V: Serialize + Send + Sync>(&self, table: &TableIdentifier, obj_id: u64, value: &V) -> anyhow::Result<()> {
        let bytes = serialize(value)?;
        let t = self.kiv_tables.entry(table.clone()).or_default();
        let entry = t.entry(obj_id).or_insert_with(|| RwLock::new(Vec::new()));
        let mut guard = entry.write();
        *guard = bytes;
        Ok(())
    }

    async fn db_insert_many_kivs<V: Serialize + Send + Sync>(
        &self,
        table: &TableIdentifier,
        rows: &[QDatabaseKeyIdValueTableRow<V>],
    ) -> anyhow::Result<()> {
        let t = self.kiv_tables.entry(table.clone()).or_default();
        for row in rows {
            let bytes = serialize(&row.value)?;
            let entry = t.entry(row.obj_id).or_insert_with(|| RwLock::new(Vec::new()));
            let mut guard = entry.write();
            *guard = bytes;
        }
        Ok(())
    }

    async fn db_insert_many_kivs_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseKeyIdValueTableRowLike<V> + Send + Sync>(
        &self,
        table: &TableIdentifier,
        rows: &[R],
    ) -> anyhow::Result<()> {
        let t = self.kiv_tables.entry(table.clone()).or_default();
        for row in rows {
            let bytes = serialize(row.get_row_value_ref())?;
            let entry = t.entry(row.get_row_obj_id()).or_insert_with(|| RwLock::new(Vec::new()));
            let mut guard = entry.write();
            *guard = bytes;
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseSingleIdMerkleReader<Hash, Hasher, TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_single_id_merkle_node_max_checkpoint(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        if let Some(t) = self.single_id_merkle.get(table) {
            if let Some(inner) = t.get(&tree_id) {
                let guard = inner.read();
                if let Some(versions) = guard.get(&key) {
                    if let Some((_, hash)) = versions.range(Reverse(checkpoint_id)..).next() {
                        return Ok(*hash);
                    }
                }
            }
        }
        Ok(Hasher::get_zero_hash((tree_height - key.level) as usize))
    }

    async fn db_select_many_single_id_merkle_nodes_max_checkpoint(
        &self,
        table: &TableIdentifier,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        let mut res = Vec::with_capacity(keys.len());
        if let Some(t) = self.single_id_merkle.get(table) {
            if let Some(inner) = t.get(&tree_id) {
                let guard = inner.read();
                for k in keys {
                    if let Some(versions) = guard.get(k) {
                        if let Some((_, hash)) = versions.range(Reverse(max_checkpoint_id)..).next() {
                            res.push(*hash);
                            continue;
                        }
                    }
                    res.push(Hasher::get_zero_hash((tree_height - k.level) as usize));
                }
                return Ok(res);
            }
        }
        Ok(keys.iter().map(|k| Hasher::get_zero_hash((tree_height - k.level) as usize)).collect())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_single_id_merkle_node(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        key: SimpleMerkleNodeKey,
        value: &Hash,
    ) -> anyhow::Result<()> {
        let t = self.single_id_merkle.entry(table.clone()).or_default();
        let inner = t.entry(tree_id).or_insert_with(|| RwLock::new(HashMap::new()));
        let mut guard = inner.write();
        let versions = guard.entry(key).or_insert_with(|| BTreeMap::new());
        versions.insert(Reverse(checkpoint_id), *value);
        Ok(())
    }

    async fn db_set_single_id_merkle_nodes_batch(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        nodes: Vec<SimpleMerkleNode<Hash>>,
    ) -> anyhow::Result<()> {
        let t = self.single_id_merkle.entry(table.clone()).or_default();
        let inner = t.entry(tree_id).or_insert_with(|| RwLock::new(HashMap::new()));
        let mut guard = inner.write();
        for node in nodes {
            let versions = guard.entry(node.key).or_insert_with(|| BTreeMap::new());
            versions.insert(Reverse(checkpoint_id), node.value);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_double_id_merkle_node_max_checkpoint(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        let dkey = QDoubleIdKey { obj_id: tree_id, secondary_id: tree_sub_id };
        if let Some(t) = self.double_id_merkle.get(table) {
            if let Some(inner) = t.get(&dkey) {
                let guard = inner.read();
                if let Some(versions) = guard.get(&key) {
                    if let Some((_, hash)) = versions.range(Reverse(checkpoint_id)..).next() {
                        return Ok(*hash);
                    }
                }
            }
        }
        Ok(Hasher::get_zero_hash((tree_height - key.level) as usize))
    }

    async fn db_select_many_double_id_merkle_nodes_max_checkpoint(
        &self,
        table: &TableIdentifier,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        let dkey = QDoubleIdKey { obj_id: tree_id, secondary_id: tree_sub_id };
        let mut res = Vec::with_capacity(keys.len());
        if let Some(t) = self.double_id_merkle.get(table) {
            if let Some(inner) = t.get(&dkey) {
                let guard = inner.read();
                for k in keys {
                    if let Some(versions) = guard.get(k) {
                        if let Some((_, hash)) = versions.range(Reverse(max_checkpoint_id)..).next() {
                            res.push(*hash);
                            continue;
                        }
                    }
                    res.push(Hasher::get_zero_hash((tree_height - k.level) as usize));
                }
                return Ok(res);
            }
        }
        Ok(keys.iter().map(|k| Hasher::get_zero_hash((tree_height - k.level) as usize)).collect())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_double_id_merkle_node(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        key: SimpleMerkleNodeKey,
        value: &Hash,
    ) -> anyhow::Result<()> {
        let dkey = QDoubleIdKey { obj_id: tree_id, secondary_id: tree_sub_id };
        let t = self.double_id_merkle.entry(table.clone()).or_default();
        let inner = t.entry(dkey).or_insert_with(|| RwLock::new(HashMap::new()));
        let mut guard = inner.write();
        let versions = guard.entry(key).or_insert_with(|| BTreeMap::new());
        versions.insert(Reverse(checkpoint_id), *value);
        Ok(())
    }

    async fn db_set_double_id_merkle_nodes_batch(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        nodes: Vec<SimpleMerkleNode<Hash>>,
    ) -> anyhow::Result<()> {
        let dkey = QDoubleIdKey { obj_id: tree_id, secondary_id: tree_sub_id };
        let t = self.double_id_merkle.entry(table.clone()).or_default();
        let inner = t.entry(dkey).or_insert_with(|| RwLock::new(HashMap::new()));
        let mut guard = inner.write();
        for node in nodes {
            let versions = guard.entry(node.key).or_insert_with(|| BTreeMap::new());
            versions.insert(Reverse(checkpoint_id), node.value);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseZeroIdMerkleReader<Hash, Hasher, TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_zero_id_merkle_node_max_checkpoint(
        &self,
        table: &TableIdentifier,
        max_checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        if let Some(inner) = self.zero_id_merkle.get(table) {
            let guard = inner.read();
            if let Some(versions) = guard.get(key) {
                if let Some((_, hash)) = versions.range(Reverse(max_checkpoint_id)..).next() {
                    return Ok(*hash);
                }
            }
        }
        Ok(Hasher::get_zero_hash(key.level as usize))
    }

    async fn db_select_many_zero_id_merkle_nodes_max_checkpoint(
        &self,
        table: &TableIdentifier,
        max_checkpoint_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        let mut res = Vec::with_capacity(keys.len());
        if let Some(inner) = self.zero_id_merkle.get(table) {
            let guard = inner.read();
            for k in keys {
                if let Some(versions) = guard.get(k) {
                    if let Some((_, hash)) = versions.range(Reverse(max_checkpoint_id)..).next() {
                        res.push(*hash);
                        continue;
                    }
                }
                res.push(Hasher::get_zero_hash(k.level as usize));
            }
            return Ok(res);
        }
        Ok(keys.iter().map(|k| Hasher::get_zero_hash(k.level as usize)).collect())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseZeroIdMerkleWriter<Hash, Hasher, TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_zero_id_merkle_node(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
        value: &Hash,
    ) -> anyhow::Result<()> {
        let inner = self.zero_id_merkle.entry(table.clone()).or_insert_with(|| RwLock::new(HashMap::new()));
        let mut guard = inner.write();
        let versions = guard.entry(*key).or_insert_with(|| BTreeMap::new());
        versions.insert(Reverse(checkpoint_id), *value);
        Ok(())
    }

    async fn db_set_zero_id_merkle_nodes_batch(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()> {
        let inner = self.zero_id_merkle.entry(table.clone()).or_insert_with(|| RwLock::new(HashMap::new()));
        let mut guard = inner.write();
        for node in nodes {
            let versions = guard.entry(node.key).or_insert_with(|| BTreeMap::new());
            versions.insert(Reverse(checkpoint_id), node.value);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseTagTreeReader<Hash, Hasher, TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_get_tag_tree_node_value(
        &self,
        table: &TableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>> {
        if let Some(t) = self.tag_trees.get(table) {
            if let Some(inner) = t.get(&unique_pending_id) {
                let guard = inner.read();
                return Ok(guard.get(key).map(|(v, _)| *v));
            }
        }
        Ok(None)
    }

    async fn db_get_tag_tree_node_values(
        &self,
        table: &TableIdentifier,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<Hash>>> {
        let mut res = Vec::with_capacity(keys.len());
        if let Some(t) = self.tag_trees.get(table) {
            if let Some(inner) = t.get(&unique_pending_id) {
                let guard = inner.read();
                for k in keys {
                    res.push(guard.get(k).map(|(v, _)| *v));
                }
                return Ok(res);
            }
        }
        res.resize(keys.len(), None);
        Ok(res)
    }

    async fn db_get_tag_tree_node_tag(
        &self,
        table: &TableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>> {
        if let Some(t) = self.tag_trees.get(table) {
            if let Some(inner) = t.get(&unique_pending_id) {
                let guard = inner.read();
                return Ok(guard.get(key).map(|(_, t)| *t));
            }
        }
        Ok(None)
    }

    async fn db_get_tag_tree_root(&self, table: &TableIdentifier, unique_pending_id: u64) -> anyhow::Result<Option<Hash>> {
        let root_key = SimpleMerkleNodeKey { level: 0, index: 0 };
        self.db_get_tag_tree_node_value(table, unique_pending_id, &root_key).await
    }

    async fn db_get_tag_tree_merkle_proof(
        &self,
        table: &TableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<TagTreeMerkleProof<Hash>> {
       let sibling_keys = key.siblings();
        let parent_keys = sibling_keys.iter().map(|s| s.parent()).collect::<Vec<_>>();
        let left_value_key = key.left_child();
        let right_value_key = key.right_child();
        let dist_from_root = key.level as usize;

        let sibling_values_fut = self.select_many_tag_tree_values::<Hash>(&session, unique_pending_id, &sibling_keys);
        let parent_tags_fut = self.select_many_tag_tree_tags::<Hash>(&session, unique_pending_id, &parent_keys);
        let left_value_fut = self.select_one_tag_tree_value::<Hash>(&session, unique_pending_id, left_value_key);
        let right_value_fut = self.select_one_tag_tree_value::<Hash>(&session, unique_pending_id, right_value_key);
        let self_tag_value_fut = self.select_one_tag_tree_tag_and_value::<Hash>(&session, unique_pending_id, &key);
        let root_key = SimpleMerkleNodeKey::new(0,0);
        let root_value_fut = self.select_one_tag_tree_value::<Hash>(&session, unique_pending_id, root_key);
        let (sibling_values, parent_tags, left_value, right_value, self_value_tag, root_value) = tokio::join!(sibling_values_fut, parent_tags_fut, left_value_fut, right_value_fut, self_tag_value_fut, root_value_fut);
        let sibling_values = sibling_values?.into_iter().flatten().collect::<Vec<_>>();
        if sibling_values.len() != dist_from_root {
            anyhow::bail!("Tag tree proof generation failed: expected {} sibling values, got {}",
                dist_from_root,
                sibling_values.len()
            );
        }
        let root_value = root_value?;
        if root_value.is_none() {
            anyhow::bail!("Tag tree proof generation failed: missing root value");
        }
        let root_value = root_value.unwrap();
        let parent_tags = parent_tags?.into_iter().flatten().collect::<Vec<_>>();
        if parent_tags.len() != dist_from_root {
            anyhow::bail!("Tag tree proof generation failed: expected {} parent tags, got {}",
                dist_from_root,
                parent_tags.len()
            );
        }
        
        let left_value = left_value?;
        let right_value = right_value?;
        let self_value_tag = self_value_tag?;
        if self_value_tag.is_none() {
            anyhow::bail!("Tag tree proof generation failed: missing self value/tag at key {:?}", key);
        }
        let self_value_tag = self_value_tag.unwrap();

        let preimage = TagTreeNodePreimage {
            left: left_value.unwrap_or_default(),
            right: right_value.unwrap_or_default(),
            tag: self_value_tag.tag,
        };

        let proof = TagTreeMerkleProof {
            index: key.index,
            leaf: preimage,
            root: root_value,
            siblings: sibling_values.iter().zip(parent_tags.iter()).map(|(sibling, parent_tag)| TagTreeProofNode {
                sibling: *sibling,
                parent_tag: *parent_tag,
            }).collect(),
        };

        Ok(proof)
    }

    async fn db_get_tag_tree_node_tags(&self, table: &TableIdentifier, unique_pending_id: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Option<Hash>>> {
        let mut res = Vec::with_capacity(keys.len());
        if let Some(t) = self.tag_trees.get(table) {
            if let Some(inner) = t.get(&unique_pending_id) {
                let guard = inner.read();
                for k in keys {
                    res.push(guard.get(k).map(|(_, t)| *t));
                }
                return Ok(res);
            }
        }
        res.resize(keys.len(), None);
        Ok(res)
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseTagTreeWriter<Hash, Hasher, TableIdentifier> for InMemoryCoreStore<Hash, Hasher>
{
    async fn set_tag_tree_tag_value(
        &self,
        table: &TableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
        tag: &Hash,
        value: &Hash,
    ) -> anyhow::Result<()> {
        let t = self.tag_trees.entry(table.clone()).or_default();
        let inner = t.entry(unique_pending_id).or_insert_with(|| RwLock::new(HashMap::new()));
        let mut guard = inner.write();
        guard.insert(*key, (*value, *tag));
        Ok(())
    }

    async fn set_tag_tree_tag(&self, table: &TableIdentifier, unique_pending_id: u64, key: &SimpleMerkleNodeKey, tag: &Hash) -> anyhow::Result<()> {
        let left = key.left_child();
        let right = key.right_child();
        let left_value = self.db_get_tag_tree_node_value(table, unique_pending_id, &left).await?.unwrap_or_default();
        let right_value = self.db_get_tag_tree_node_value(table, unique_pending_id, &right).await?.unwrap_or_default();
        let new_value = Hasher::two_to_one(&left_value, &right_value);  // Assume tag is not used here? Wait, from Scylla, hash_tag_tree_node(&left, &right, tag)
        // Assuming hash_tag_tree_node is Hasher::two_to_one(left, right) but with tag? Wait, from provided code, it's two_to_one, but in tag_tree, likely custom.
        // From provided, hash_tag_tree_node::<Hash, Hasher>(&left, &right, &tag)
        // Assume it's Hasher::two_to_one_swap or something, but to match, assume it's defined as Hasher::two_to_one(&Hasher::two_to_one(left, right), tag) or something.
        // Since not defined, use Hasher::two_to_one(left, right) as value, but trait is MerkleHasher, so two_to_one.
        // But for tag, perhaps value = two_to_one(left, right), but with tag? Wait, perhaps value is two_to_one(tag, two_to_one(left, right))
        // To match Scylla, assume a function hash_tag_tree_node which is Hasher::two_to_one(left, right) or custom.
        // Since not in provided, I'll use Hasher::two_to_one(&left_value, &right_value)
        let new_value = Hasher::two_to_one(&left_value, &right_value);
        self.set_tag_tree_tag_value(table, unique_pending_id, key, tag, &new_value).await
    }
}
