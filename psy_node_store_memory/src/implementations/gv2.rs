// https://aistudio.google.com/prompts/1n5wcR03GMWXxNIs_cIHOwvUh75arh3-D?_gl=1*m14tst*_ga*MTQ4NDUwODIzMi4xNzQyNjUzNzMx*_ga_P1DBVKWT6V*MTc0MjY1MzczMC4xLjAuMTc0MjY1MzczMy41Ny4wLjk4OTg3NDExNg..

use anyhow::{Context, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use parth_core::{
    crypto::hash::{tag_tree::TagTreeMerkleProof, traits::MerkleZeroHasher},
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
    protocol::core_types::{QDBHashBase, QHashBase},
};

use psy_node_core::store::traits::core_db::{
    CoreDatabaseBidirectionalMappingReader, CoreDatabaseBidirectionalMappingWriter, CoreDatabaseBidirectionalU64U128MappingReader, CoreDatabaseBidirectionalU64U128MappingWriter, CoreDatabaseDoubleIdCheckpointedReader, CoreDatabaseDoubleIdCheckpointedWriter, CoreDatabaseDoubleIdMerkleReader, CoreDatabaseDoubleIdMerkleWriter, CoreDatabaseKivReader, CoreDatabaseKivWriter, CoreDatabaseSingleIdCheckpointedReader, CoreDatabaseSingleIdCheckpointedWriter, CoreDatabaseSingleIdMerkleReader, CoreDatabaseSingleIdMerkleWriter, CoreDatabaseStore, CoreDatabaseTagTreeReader, CoreDatabaseTagTreeStore, CoreDatabaseTagTreeWriter, CoreDatabaseU64Reader, CoreDatabaseU64Writer, CoreDatabaseZeroIdMerkleReader, CoreDatabaseZeroIdMerkleWriter
};


use serde::{de::DeserializeOwned, Serialize};
use std::{collections::BTreeMap, marker::PhantomData};

use crate::utils::TIDBase;


/// An ultra-fast, concurrent, in-memory database store.
///
/// This store uses `DashMap` for fine-grained, sharded locking at the table and key level,
/// ensuring high performance under concurrent workloads. For checkpointed data, it uses
/// `BTreeMap` to enable efficient "point-in-time" queries, a critical feature for
/// blockchain-like state engines.
#[derive(Debug)]
pub struct InMemoryStore<
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase, // BiDirectionalMappingTableIdentifier
    BU_TID: TIDBase, // BiDirectionalU64U128MappingTableIdentifier
    U64_TID: TIDBase, // U64TableIdentifier
    SI_TID: TIDBase,  // SingleIdTableIdentifier
    DI_TID: TIDBase,  // DoubleIdTableIdentifier
    KIV_TID: TIDBase, // KivTableIdentifier
    SIM_TID: TIDBase, // SingleIdMerkleTableIdentifier
    DIM_TID: TIDBase, // DoubleIdMerkleTableIdentifier
    ZIM_TID: TIDBase, // ZeroIdMerkleTableIdentifier
    TT_TID: TIDBase,  // TagTreeTableIdentifier
> {
    bidirectional_mapping_tables: DashMap<BM_TID, (DashMap<Vec<u8>, Vec<u8>>, DashMap<Vec<u8>, Vec<u8>>)>,
    bidirectional_u64_u128_mapping_tables: DashMap<BU_TID, (DashMap<u64, u128>, DashMap<u128, u64>)>,
    u64_tables: DashMap<U64_TID, DashMap<u64, u64>>,
    single_id_checkpointed_tables: DashMap<SI_TID, DashMap<u64, BTreeMap<u64, Vec<u8>>>>,
    double_id_checkpointed_tables: DashMap<DI_TID, DashMap<QDoubleIdKey, BTreeMap<u64, Vec<u8>>>>,
    kiv_tables: DashMap<KIV_TID, DashMap<u64, Vec<u8>>>,
    single_id_merkle_tables: DashMap<SIM_TID, DashMap<(u64, SimpleMerkleNodeKey), BTreeMap<u64, Hash>>>,
    double_id_merkle_tables: DashMap<DIM_TID, DashMap<(u64, u64, SimpleMerkleNodeKey), BTreeMap<u64, Hash>>>,
    zero_id_merkle_tables: DashMap<ZIM_TID, DashMap<SimpleMerkleNodeKey, BTreeMap<u64, Hash>>>,
    tag_tree_tables: DashMap<TT_TID, DashMap<(u64, SimpleMerkleNodeKey), (Hash, Hash)>>,
    _phantom: PhantomData<Hasher>,
}

impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    /// Creates a new, empty `InMemoryStore`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID> Default
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    fn default() -> Self {
        Self {
            bidirectional_mapping_tables: DashMap::new(),
            bidirectional_u64_u128_mapping_tables: DashMap::new(),
            u64_tables: DashMap::new(),
            single_id_checkpointed_tables: DashMap::new(),
            double_id_checkpointed_tables: DashMap::new(),
            kiv_tables: DashMap::new(),
            single_id_merkle_tables: DashMap::new(),
            double_id_merkle_tables: DashMap::new(),
            zero_id_merkle_tables: DashMap::new(),
            tag_tree_tables: DashMap::new(),
            _phantom: PhantomData,
        }
    }
}

// Internal helper for deserialization, honoring the custom trait
fn deserialize_value<V: CoreDatabaseValueDeserialize>(bytes: &[u8]) -> Result<V> {
    pser::deserialize(bytes).with_context(|| "Failed to deserialize value from DB bytes")
}

// Internal helper for serialization using bincode for efficiency
fn serialize_value<V: Serialize>(value: &V) -> Result<Vec<u8>> {
    pser::serialize(value).with_context(|| "Failed to serialize value to bytes")
}

// Now, we implement every required trait for InMemoryStore.

#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseBidirectionalMappingReader<BM_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_select_one_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BM_TID,
        k1: &K1,
    ) -> Result<Option<K2>> {
        if let Some(table_ref) = self.bidirectional_mapping_tables.get(table) {
            let k1_bytes = k1.to_bytes()?;
            if let Some(k2_bytes) = table_ref.0.get(&k1_bytes) {
                return Ok(Some(K2::from_bytes(&k2_bytes)?));
            }
        }
        Ok(None)
    }

    async fn db_select_one_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BM_TID,
        k2: &K2,
    ) -> Result<Option<K1>> {
        if let Some(table_ref) = self.bidirectional_mapping_tables.get(table) {
            let k2_bytes = k2.to_bytes()?;
            if let Some(k1_bytes) = table_ref.1.get(&k2_bytes) {
                return Ok(Some(K1::from_bytes(&k1_bytes)?));
            }
        }
        Ok(None)
    }

    async fn db_select_many_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BM_TID,
        k1s: &[K1],
    ) -> Result<Vec<Option<K2>>> {
        let mut results = Vec::with_capacity(k1s.len());
        if let Some(table_ref) = self.bidirectional_mapping_tables.get(table) {
            for k1 in k1s {
                let k1_bytes = k1.to_bytes()?;
                let result = table_ref.0.get(&k1_bytes)
                    .map(|k2_bytes| K2::from_bytes(&k2_bytes))
                    .transpose()?;
                results.push(result);
            }
        } else {
            for _ in k1s {
                results.push(None);
            }
        }
        Ok(results)
    }

    async fn db_select_many_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BM_TID,
        k2s: &[K2],
    ) -> Result<Vec<Option<K1>>> {
        let mut results = Vec::with_capacity(k2s.len());
        if let Some(table_ref) = self.bidirectional_mapping_tables.get(table) {
            for k2 in k2s {
                let k2_bytes = k2.to_bytes()?;
                let result = table_ref.1.get(&k2_bytes)
                    .map(|k1_bytes| K1::from_bytes(&k1_bytes))
                    .transpose()?;
                results.push(result);
            }
        } else {
            for _ in k2s {
                results.push(None);
            }
        }
        Ok(results)
    }

    async fn db_select_many_pairs_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BM_TID,
        k1s: &[K1],
    ) -> Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        let mut results = Vec::new();
        if let Some(table_ref) = self.bidirectional_mapping_tables.get(table) {
            for k1 in k1s {
                let k1_bytes = k1.to_bytes()?;
                if let Some(k2_bytes) = table_ref.0.get(&k1_bytes) {
                    results.push(BiDirectionalMappingRow {
                        k1: k1.clone(),
                        k2: K2::from_bytes(&k2_bytes)?,
                    });
                }
            }
        }
        Ok(results)
    }
    
    async fn db_select_many_pairs_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BM_TID,
        k2s: &[K2],
    ) -> Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        let mut results = Vec::new();
        if let Some(table_ref) = self.bidirectional_mapping_tables.get(table) {
            for k2 in k2s {
                let k2_bytes = k2.to_bytes()?;
                if let Some(k1_bytes) = table_ref.1.get(&k2_bytes) {
                    results.push(BiDirectionalMappingRow {
                        k1: K1::from_bytes(&k1_bytes)?,
                        k2: k2.clone(),
                    });
                }
            }
        }
        Ok(results)
    }

    async fn db_select_all_pairs_from_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BM_TID,
        start_k1: Option<K1>,
        max_count: usize,
    ) -> Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        let mut results = Vec::new();
        if let Some(table_ref) = self.bidirectional_mapping_tables.get(table) {
            let start_bytes = match start_k1 {
                Some(k) => Some(k.to_bytes()?),
                None => None,
            };
            
            // Note: DashMap iteration order is not guaranteed. For a true "start_k1",
            // a sorted concurrent map would be needed. This implementation returns an arbitrary set.
            let iter = table_ref.0.iter();
            let mut vec: Vec<_> = iter.collect();
            vec.sort_by(|a, b| a.key().cmp(b.key()));
            let skipped_iter: Box<dyn Iterator<Item = dashmap::mapref::multiple::RefMulti<'_, Vec<u8>, Vec<u8>>>>
                = if let Some(start) = start_bytes {
                    Box::new(vec.into_iter().skip_while(move |entry| entry.key() < &start))
                } else {
                    Box::new(vec.into_iter())
                };

            for item in skipped_iter.take(max_count) {
                 results.push(BiDirectionalMappingRow {
                    k1: K1::from_bytes(item.key())?,
                    k2: K2::from_bytes(item.value())?,
                });
            }
        }
        Ok(results)
    }
}

#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseBidirectionalMappingWriter<BM_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_insert_pair_ref<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BM_TID,
        k1: &K1,
        k2: &K2,
    ) -> Result<()> {
        let mut table_ref = self
            .bidirectional_mapping_tables
            .entry(table.clone())
            .or_insert_with(|| (DashMap::new(), DashMap::new()));

        let k1_bytes = k1.to_bytes()?;
        let k2_bytes = k2.to_bytes()?;

        // These operations are individually atomic, and holding the lock on the outer
        // DashMap entry ensures no other thread can modify the tuple of inner maps.
        table_ref.0.insert(k1_bytes.clone(), k2_bytes.clone());
        table_ref.1.insert(k2_bytes, k1_bytes);
        Ok(())
    }

    async fn db_insert_pair<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BM_TID,
        k1: K1,
        k2: K2,
    ) -> Result<()> {
        self.db_insert_pair_ref(table, &k1, &k2).await
    }
    
    async fn db_insert_pairs<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BM_TID,
        keys: &[BiDirectionalMappingRow<K1, K2>],
    ) -> Result<()> {
        let mut table_ref = self
            .bidirectional_mapping_tables
            .entry(table.clone())
            .or_insert_with(|| (DashMap::new(), DashMap::new()));

        for row in keys {
            let k1_bytes = row.k1.to_bytes()?;
            let k2_bytes = row.k2.to_bytes()?;
            table_ref.0.insert(k1_bytes.clone(), k2_bytes.clone());
            table_ref.1.insert(k2_bytes, k1_bytes);
        }
        Ok(())
    }
}


#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseBidirectionalU64U128MappingReader<BU_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_select_one_u128_value_by_u64(&self, table: &BU_TID, key: u64) -> Result<Option<u128>> {
        Ok(self.bidirectional_u64_u128_mapping_tables
            .get(table)
            .and_then(|table_ref| table_ref.0.get(&key).map(|v| *v)))
    }

    async fn db_select_one_u64_key_by_u128(&self, table: &BU_TID, value: u128) -> Result<Option<u64>> {
        Ok(self.bidirectional_u64_u128_mapping_tables
            .get(table)
            .and_then(|table_ref| table_ref.1.get(&value).map(|v| *v)))
    }

    async fn db_select_many_u128_values_by_u64s(&self, table: &BU_TID, keys: &[u64]) -> Result<Vec<Option<u128>>> {
        let mut results = Vec::with_capacity(keys.len());
        if let Some(table_ref) = self.bidirectional_u64_u128_mapping_tables.get(table) {
            for key in keys {
                results.push(table_ref.0.get(key).map(|v| *v));
            }
        } else {
            for _ in keys {
                results.push(None);
            }
        }
        Ok(results)
    }

    async fn db_select_many_u64_keys_by_u128s(&self, table: &BU_TID, values: &[u128]) -> Result<Vec<Option<u64>>> {
        let mut results = Vec::with_capacity(values.len());
        if let Some(table_ref) = self.bidirectional_u64_u128_mapping_tables.get(table) {
            for value in values {
                results.push(table_ref.1.get(value).map(|v| *v));
            }
        } else {
            for _ in values {
                results.push(None);
            }
        }
        Ok(results)
    }
}

#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseBidirectionalU64U128MappingWriter<BU_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_insert_u64_u128_mapping_pair(&self, table: &BU_TID, k1: u64, k2: u128) -> Result<()> {
        let mut table_ref = self
            .bidirectional_u64_u128_mapping_tables
            .entry(table.clone())
            .or_insert_with(|| (DashMap::new(), DashMap::new()));
        
        table_ref.0.insert(k1, k2);
        table_ref.1.insert(k2, k1);
        Ok(())
    }

    async fn db_insert_u64_u128_mapping_pairs(&self, table: &BU_TID, keys: &[BiDirectionalMappingRow<u64, u128>]) -> Result<()> {
        let mut table_ref = self
            .bidirectional_u64_u128_mapping_tables
            .entry(table.clone())
            .or_insert_with(|| (DashMap::new(), DashMap::new()));

        for row in keys {
            table_ref.0.insert(row.k1, row.k2);
            table_ref.1.insert(row.k2, row.k1);
        }
        Ok(())
    }
}


#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseU64Reader<U64_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_select_u64_value(&self, table: &U64_TID, obj_id: u64) -> Result<Option<u64>> {
        Ok(self.u64_tables
            .get(table)
            .and_then(|inner_map| inner_map.get(&obj_id).map(|v| *v)))
    }

    async fn db_select_u64_values(&self, table: &U64_TID, obj_ids: &[u64]) -> Result<Vec<Option<u64>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        if let Some(inner_map) = self.u64_tables.get(table) {
            for obj_id in obj_ids {
                results.push(inner_map.get(obj_id).map(|v| *v));
            }
        } else {
            for _ in obj_ids {
                results.push(None);
            }
        }
        Ok(results)
    }
}

#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseU64Writer<U64_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_inc_counter(&self, table: &U64_TID, obj_id: u64, amount: i64) -> Result<u64> {
        let inner_map = self.u64_tables.entry(table.clone()).or_default();
        let mut entry = inner_map.entry(obj_id).or_insert(0);
        
        if amount > 0 {
            *entry = entry.saturating_add(amount as u64);
        } else {
            *entry = entry.saturating_sub(amount.unsigned_abs());
        }
        
        Ok(*entry)
    }

    async fn db_set_u64_value(&self, table: &U64_TID, obj_id: u64, value: u64) -> Result<()> {
        self.u64_tables
            .entry(table.clone())
            .or_default()
            .insert(obj_id, value);
        Ok(())
    }

    async fn db_set_many_u64_values(&self, table: &U64_TID, rows: &[QPDPair<u64, u64>]) -> Result<()> {
        let inner_map = self.u64_tables.entry(table.clone()).or_default();
        for row in rows {
            inner_map.insert(row.key, row.value);
        }
        Ok(())
    }
}


#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseSingleIdCheckpointedReader<SI_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_select_one_single_checkpointed_object_value<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &SI_TID,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> Result<Option<V>> {
        if let Some(inner_map) = self.single_id_checkpointed_tables.get(table) {
            if let Some(version_map) = inner_map.get(&obj_id) {
                if let Some((_, value_bytes)) = version_map.range(..=max_checkpoint_id).next_back() {
                    return Ok(Some(deserialize_value(value_bytes)?));
                }
            }
        }
        Ok(None)
    }

    async fn db_select_one_single_checkpointed_object_value_and_ids<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &SI_TID,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> Result<Option<QDatabaseSingleIdTableRow<V>>> {
        if let Some(inner_map) = self.single_id_checkpointed_tables.get(table) {
            if let Some(version_map) = inner_map.get(&obj_id) {
                if let Some((&checkpoint_id, value_bytes)) = version_map.range(..=max_checkpoint_id).next_back() {
                    return Ok(Some(QDatabaseSingleIdTableRow {
                        obj_id,
                        checkpoint_id,
                        value: deserialize_value(value_bytes)?,
                    }));
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
        table: &SI_TID,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> Result<Option<R>> {
        if let Some(row) = self.db_select_one_single_checkpointed_object_value_and_ids(table, obj_id, max_checkpoint_id).await? {
            return Ok(Some(R::create_from_single_row(row.obj_id, row.checkpoint_id, row.value)));
        }
        Ok(None)
    }

    async fn db_select_all_single_checkpointed_object<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &SI_TID,
    ) -> Result<Vec<QDatabaseSingleIdTableRow<V>>> {
        let mut results = Vec::new();
        if let Some(inner_map) = self.single_id_checkpointed_tables.get(table) {
            for entry in inner_map.iter() {
                let obj_id = *entry.key();
                for (&checkpoint_id, value_bytes) in entry.value().iter() {
                    results.push(QDatabaseSingleIdTableRow {
                        obj_id,
                        checkpoint_id,
                        value: deserialize_value(value_bytes)?,
                    });
                }
            }
        }
        Ok(results)
    }

    async fn db_select_many_single_checkpointed_object_values<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &SI_TID,
        obj_ids: &[u64],
        max_checkpoint_id: u64,
    ) -> Result<Vec<Option<V>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        for &obj_id in obj_ids {
            let value = self.db_select_one_single_checkpointed_object_value(table, obj_id, max_checkpoint_id).await?;
            results.push(value);
        }
        Ok(results)
    }

    async fn db_select_many_single_checkpointed_object_keys_and_values<
        V: CoreDatabaseValueDeserialize,
        R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &SI_TID,
        obj_ids: &[u64],
        max_checkpoint_id: u64,
    ) -> Result<Vec<R>> {
        let mut results = Vec::new();
        for &obj_id in obj_ids {
            if let Some(row) = self.db_select_one_single_checkpointed_object_value_and_ids_t(table, obj_id, max_checkpoint_id).await? {
                results.push(row);
            }
        }
        Ok(results)
    }
}

#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseSingleIdCheckpointedWriter<SI_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_insert_one_single_checkpointed_object<V: Serialize + Send + Sync>(
        &self,
        table: &SI_TID,
        obj_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> Result<()> {
        let inner_map = self.single_id_checkpointed_tables.entry(table.clone()).or_default();
        let value_bytes = serialize_value(value)?;
        inner_map.entry(obj_id).or_default().insert(checkpoint_id, value_bytes);
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_object_rows<V: Serialize + Send + Sync>(
        &self,
        table: &SI_TID,
        rows: &[QDatabaseSingleIdTableRow<V>],
    ) -> Result<()> {
        let inner_map = self.single_id_checkpointed_tables.entry(table.clone()).or_default();
        for row in rows {
            let value_bytes = serialize_value(&row.value)?;
            inner_map.entry(row.obj_id).or_default().insert(row.checkpoint_id, value_bytes);
        }
        Ok(())
    }
    
    async fn db_insert_many_single_checkpointed_object_rows_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseSingleIdTableRowLike<V> + Send + Sync,
    >(
        &self,
        table: &SI_TID,
        rows: &[R],
    ) -> Result<()> {
        let inner_map = self.single_id_checkpointed_tables.entry(table.clone()).or_default();
        for row in rows {
            let value_bytes = serialize_value(row.get_row_value_ref())?;
            inner_map.entry(row.get_row_obj_id()).or_default().insert(row.get_row_checkpoint_id(), value_bytes);
        }
        Ok(())
    }
    
    async fn db_insert_many_single_checkpointed_objects_at_checkpoint<V: Serialize + Send + Sync>(
        &self,
        table: &SI_TID,
        checkpoint_id: u64,
        rows: &[QDatabaseSingleIdTableRowNoCheckpointId<V>],
    ) -> Result<()> {
        let inner_map = self.single_id_checkpointed_tables.entry(table.clone()).or_default();
        for row in rows {
            let value_bytes = serialize_value(&row.value)?;
            inner_map.entry(row.obj_id).or_default().insert(checkpoint_id, value_bytes);
        }
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseSingleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &SI_TID,
        checkpoint_id: u64,
        rows: &[R],
    ) -> Result<()> {
        let inner_map = self.single_id_checkpointed_tables.entry(table.clone()).or_default();
        for row in rows {
            let value_bytes = serialize_value(row.get_row_value_ref())?;
            inner_map.entry(row.get_row_obj_id()).or_default().insert(checkpoint_id, value_bytes);
        }
        Ok(())
    }
}


#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseDoubleIdCheckpointedReader<DI_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_select_one_double_checkpointed_object_value<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &DI_TID,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> Result<Option<V>> {
        let key = QDoubleIdKey { obj_id, secondary_id };
        if let Some(inner_map) = self.double_id_checkpointed_tables.get(table) {
            if let Some(version_map) = inner_map.get(&key) {
                if let Some((_, value_bytes)) = version_map.range(..=max_checkpoint_id).next_back() {
                    return Ok(Some(deserialize_value(value_bytes)?));
                }
            }
        }
        Ok(None)
    }

    async fn db_select_one_double_checkpointed_object_value_and_ids<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &DI_TID,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> Result<Option<QDatabaseDoubleIdTableRow<V>>> {
        let key = QDoubleIdKey { obj_id, secondary_id };
        if let Some(inner_map) = self.double_id_checkpointed_tables.get(table) {
            if let Some(version_map) = inner_map.get(&key) {
                if let Some((&checkpoint_id, value_bytes)) = version_map.range(..=max_checkpoint_id).next_back() {
                    return Ok(Some(QDatabaseDoubleIdTableRow {
                        obj_id,
                        secondary_id,
                        checkpoint_id,
                        value: deserialize_value(value_bytes)?,
                    }));
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
        table: &DI_TID,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> Result<Option<R>> {
        if let Some(row) = self.db_select_one_double_checkpointed_object_value_and_ids(table, obj_id, secondary_id, max_checkpoint_id).await? {
            return Ok(Some(R::create_from_double_row(row.obj_id, row.secondary_id, row.checkpoint_id, row.value)));
        }
        Ok(None)
    }

    async fn db_select_all_double_checkpointed_object<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &DI_TID,
    ) -> Result<Vec<QDatabaseDoubleIdTableRow<V>>> {
        let mut results = Vec::new();
        if let Some(inner_map) = self.double_id_checkpointed_tables.get(table) {
            for entry in inner_map.iter() {
                let key = entry.key();
                for (&checkpoint_id, value_bytes) in entry.value().iter() {
                    results.push(QDatabaseDoubleIdTableRow {
                        obj_id: key.obj_id,
                        secondary_id: key.secondary_id,
                        checkpoint_id,
                        value: deserialize_value(value_bytes)?,
                    });
                }
            }
        }
        Ok(results)
    }

    async fn db_select_many_double_checkpointed_object_values<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &DI_TID,
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> Result<Vec<Option<V>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        for key in obj_ids {
            let value = self.db_select_one_double_checkpointed_object_value(table, key.obj_id, key.secondary_id, max_checkpoint_id).await?;
            results.push(value);
        }
        Ok(results)
    }

    async fn db_select_many_double_checkpointed_object_keys_and_values<
        V: CoreDatabaseValueDeserialize,
        R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &DI_TID,
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> Result<Vec<R>> {
        let mut results = Vec::new();
        for key in obj_ids {
            if let Some(row) = self.db_select_one_double_checkpointed_object_value_and_ids_t(table, key.obj_id, key.secondary_id, max_checkpoint_id).await? {
                results.push(row);
            }
        }
        Ok(results)
    }
}

#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseDoubleIdCheckpointedWriter<DI_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_insert_one_double_checkpointed_object<V: Serialize + Send + Sync>(
        &self,
        table: &DI_TID,
        obj_id: u64,
        secondary_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> Result<()> {
        let inner_map = self.double_id_checkpointed_tables.entry(table.clone()).or_default();
        let key = QDoubleIdKey { obj_id, secondary_id };
        let value_bytes = serialize_value(value)?;
        inner_map.entry(key).or_default().insert(checkpoint_id, value_bytes);
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_object_rows<V: Serialize + Send + Sync>(
        &self,
        table: &DI_TID,
        rows: &[QDatabaseDoubleIdTableRow<V>],
    ) -> Result<()> {
        let inner_map = self.double_id_checkpointed_tables.entry(table.clone()).or_default();
        for row in rows {
            let key = QDoubleIdKey { obj_id: row.obj_id, secondary_id: row.secondary_id };
            let value_bytes = serialize_value(&row.value)?;
            inner_map.entry(key).or_default().insert(row.checkpoint_id, value_bytes);
        }
        Ok(())
    }
    
    async fn db_insert_many_double_checkpointed_object_rows_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseDoubleIdTableRowLike<V> + Send + Sync,
    >(
        &self,
        table: &DI_TID,
        rows: &[R],
    ) -> Result<()> {
        let inner_map = self.double_id_checkpointed_tables.entry(table.clone()).or_default();
        for row in rows {
            let key = QDoubleIdKey { obj_id: row.get_row_obj_id(), secondary_id: row.get_row_secondary_id() };
            let value_bytes = serialize_value(row.get_row_value_ref())?;
            inner_map.entry(key).or_default().insert(row.get_row_checkpoint_id(), value_bytes);
        }
        Ok(())
    }
    
    async fn db_insert_many_double_checkpointed_objects_at_checkpoint<V: Serialize + Send + Sync>(
        &self,
        table: &DI_TID,
        checkpoint_id: u64,
        rows: &[QDatabaseDoubleIdTableRowNoCheckpointId<V>],
    ) -> Result<()> {
        let inner_map = self.double_id_checkpointed_tables.entry(table.clone()).or_default();
        for row in rows {
            let key = QDoubleIdKey { obj_id: row.obj_id, secondary_id: row.secondary_id };
            let value_bytes = serialize_value(&row.value)?;
            inner_map.entry(key).or_default().insert(checkpoint_id, value_bytes);
        }
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_objects_at_checkpoint_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseDoubleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &DI_TID,
        checkpoint_id: u64,
        rows: &[R],
    ) -> Result<()> {
        let inner_map = self.double_id_checkpointed_tables.entry(table.clone()).or_default();
        for row in rows {
            let key = QDoubleIdKey { obj_id: row.get_row_obj_id(), secondary_id: row.get_row_secondary_id() };
            let value_bytes = serialize_value(row.get_row_value_ref())?;
            inner_map.entry(key).or_default().insert(checkpoint_id, value_bytes);
        }
        Ok(())
    }
}


#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseKivReader<KIV_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_select_one_kiv_value<V: CoreDatabaseValueDeserialize>(&self, table: &KIV_TID, obj_id: u64) -> Result<Option<V>> {
        if let Some(inner_map) = self.kiv_tables.get(table) {
            if let Some(value_bytes) = inner_map.get(&obj_id) {
                return Ok(Some(deserialize_value(&value_bytes)?));
            }
        }
        Ok(None)
    }

    async fn db_select_one_kiv_value_and_ids<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &KIV_TID,
        obj_id: u64,
    ) -> Result<Option<QDatabaseKeyIdValueTableRow<V>>> {
        if let Some(value) = self.db_select_one_kiv_value(table, obj_id).await? {
            return Ok(Some(QDatabaseKeyIdValueTableRow { obj_id, value }));
        }
        Ok(None)
    }

    async fn db_select_one_kiv_value_and_ids_t<V: CoreDatabaseValueDeserialize, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(
        &self,
        table: &KIV_TID,
        obj_id: u64,
    ) -> Result<Option<R>> {
        if let Some(value) = self.db_select_one_kiv_value(table, obj_id).await? {
            return Ok(Some(R::create_from_key_id_value_row(obj_id, value)));
        }
        Ok(None)
    }

    async fn db_select_all_kiv<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &KIV_TID,
    ) -> Result<Vec<QDatabaseKeyIdValueTableRow<V>>> {
        let mut results = Vec::new();
        if let Some(inner_map) = self.kiv_tables.get(table) {
            for entry in inner_map.iter() {
                results.push(QDatabaseKeyIdValueTableRow {
                    obj_id: *entry.key(),
                    value: deserialize_value(entry.value())?,
                });
            }
        }
        Ok(results)
    }

    async fn db_select_many_kiv_values<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &KIV_TID,
        obj_ids: &[u64],
    ) -> Result<Vec<Option<V>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        if let Some(inner_map) = self.kiv_tables.get(table) {
            for &obj_id in obj_ids {
                let value = inner_map.get(&obj_id).map(|v_bytes| deserialize_value(&v_bytes)).transpose()?;
                results.push(value);
            }
        } else {
            for _ in obj_ids {
                results.push(None);
            }
        }
        Ok(results)
    }

    async fn db_select_many_kiv_keys_and_values<V: CoreDatabaseValueDeserialize, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(
        &self,
        table: &KIV_TID,
        obj_ids: &[u64],
    ) -> Result<Vec<R>> {
        let mut results = Vec::new();
        if let Some(inner_map) = self.kiv_tables.get(table) {
            for &obj_id in obj_ids {
                if let Some(value_bytes) = inner_map.get(&obj_id) {
                    let value = deserialize_value(&value_bytes)?;
                    results.push(R::create_from_key_id_value_row(obj_id, value));
                }
            }
        }
        Ok(results)
    }
}

#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseKivWriter<KIV_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_insert_one_kiv<V: Serialize + Send + Sync>(&self, table: &KIV_TID, obj_id: u64, value: &V) -> Result<()> {
        let value_bytes = serialize_value(value)?;
        self.kiv_tables.entry(table.clone()).or_default().insert(obj_id, value_bytes);
        Ok(())
    }

    async fn db_insert_many_kivs<V: Serialize + Send + Sync>(
        &self,
        table: &KIV_TID,
        rows: &[QDatabaseKeyIdValueTableRow<V>],
    ) -> Result<()> {
        let inner_map = self.kiv_tables.entry(table.clone()).or_default();
        for row in rows {
            let value_bytes = serialize_value(&row.value)?;
            inner_map.insert(row.obj_id, value_bytes);
        }
        Ok(())
    }

    async fn db_insert_many_kivs_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseKeyIdValueTableRowLike<V> + Send + Sync>(
        &self,
        table: &KIV_TID,
        rows: &[R],
    ) -> Result<()> {
        let inner_map = self.kiv_tables.entry(table.clone()).or_default();
        for row in rows {
            let value_bytes = serialize_value(row.get_row_value_ref())?;
            inner_map.insert(row.get_row_obj_id(), value_bytes);
        }
        Ok(())
    }
}


#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseSingleIdMerkleReader<Hash, Hasher, SIM_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_select_single_id_merkle_node_max_checkpoint(
        &self,
        table: &SIM_TID,
        checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> Result<Hash> {
        let composite_key = (tree_id, key);
        let hash = self.single_id_merkle_tables.get(table)
            .and_then(|inner_map| inner_map.get(&composite_key).map(|v| v.clone().to_owned()))
            .and_then(|version_map| version_map.range(..=checkpoint_id).next_back().map(|(_, &h)| h))
            .unwrap_or_else(|| Hasher::get_zero_hash(tree_height as usize - key.level as usize));
        Ok(hash)
    }

    async fn db_select_many_single_id_merkle_nodes_max_checkpoint(
        &self,
        table: &SIM_TID,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> Result<Vec<Hash>> {
        let mut results = Vec::with_capacity(keys.len());
        if let Some(inner_map) = self.single_id_merkle_tables.get(table) {
            for &key in keys {
                let composite_key = (tree_id, key);
                let hash = inner_map.get(&composite_key)
                    .and_then(|version_map| version_map.range(..=max_checkpoint_id).next_back().map(|(_, &h)| h))
                    .unwrap_or_else(|| Hasher::get_zero_hash(tree_height as usize - key.level as usize));
                results.push(hash);
            }
        } else {
            for &key in keys {
                results.push(Hasher::get_zero_hash(tree_height as usize - key.level as usize));
            }
        }
        Ok(results)
    }
}

#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, SIM_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_insert_single_id_merkle_node(
        &self,
        table: &SIM_TID,
        checkpoint_id: u64,
        tree_id: u64,
        key: SimpleMerkleNodeKey,
        value: &Hash,
    ) -> Result<()> {
        let inner_map = self.single_id_merkle_tables.entry(table.clone()).or_default();
        let composite_key = (tree_id, key);
        inner_map.entry(composite_key).or_default().insert(checkpoint_id, *value);
        Ok(())
    }

    async fn db_set_single_id_merkle_nodes_batch(
        &self,
        table: &SIM_TID,
        checkpoint_id: u64,
        tree_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> Result<()> {
        let inner_map = self.single_id_merkle_tables.entry(table.clone()).or_default();
        for node in nodes {
            let composite_key = (tree_id, node.key);
            inner_map.entry(composite_key).or_default().insert(checkpoint_id, node.value);
        }
        Ok(())
    }
    async fn db_set_single_id_merkle_nodes_from_fast_serialized(
        &self,
        table: &SIM_TID,
        checkpoint_id: u64,
        nodes: &[u8],
    ) -> anyhow::Result<()> {
        todo!("not implemented");
    }
}


#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseTagTreeReader<Hash, Hasher, TT_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_get_tag_tree_node_value(
        &self,
        table: &TT_TID,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> Result<Option<Hash>> {
        Ok(self.tag_tree_tables.get(table)
            .and_then(|inner_map| inner_map.get(&(unique_pending_id, *key)).map(|pair| pair.1.clone().to_owned())))
    }

    async fn db_get_tag_tree_node_values(
        &self,
        table: &TT_TID,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> Result<Vec<Option<Hash>>> {
        let mut results = Vec::with_capacity(keys.len());
        if let Some(inner_map) = self.tag_tree_tables.get(table) {
            for key in keys {
                results.push(inner_map.get(&(unique_pending_id, *key)).map(|pair| pair.1.clone()));
            }
        } else {
            for _ in keys {
                results.push(None);
            }
        }
        Ok(results)
    }

    async fn db_get_tag_tree_node_tag(
        &self,
        table: &TT_TID,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> Result<Option<Hash>> {
        Ok(self.tag_tree_tables.get(table)
            .and_then(|inner_map| inner_map.get(&(unique_pending_id, *key)).map(|pair| pair.0.clone())))
    }

    async fn db_get_tag_tree_root(&self, table: &TT_TID, unique_pending_id: u64) -> Result<Option<Hash>> {
        let root_key = SimpleMerkleNodeKey::new_root(); // Assuming max height 64
        self.db_get_tag_tree_node_tag(table, unique_pending_id, &root_key).await
    }

    async fn db_get_tag_tree_merkle_proof(
        &self,
        table: &TT_TID,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> Result<TagTreeMerkleProof<Hash>> {
        todo!("In-memory store does not support generating Merkle proofs");
    }
}

#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseTagTreeWriter<Hash, Hasher, TT_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn set_tag_tree_tag_known_height(&self, table: &TT_TID, unique_pending_id: u64, _tag_tree_height: u8, key: &SimpleMerkleNodeKey, tag: &Hash) -> Result<()> {
        let inner_map = self.tag_tree_tables.entry(table.clone()).or_default();
        let mut entry = inner_map.entry((unique_pending_id, *key)).or_insert((*tag, Hash::get_zero_value()));
        entry.0 = *tag;
        Ok(())
    }
    async fn set_tag_tree_tag_value(
        &self,
        table: &TT_TID,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
        tag: &Hash,
        value: &Hash,
    ) -> Result<()> {
        let inner_map = self.tag_tree_tables.entry(table.clone()).or_default();
        inner_map.insert((unique_pending_id, *key), (*tag, *value));
        Ok(())
    }
    
    async fn set_tag_tree_tag(&self, table: &TT_TID, unique_pending_id: u64, key: &SimpleMerkleNodeKey, tag: &Hash) -> Result<()> {
        let inner_map = self.tag_tree_tables.entry(table.clone()).or_default();
        let mut entry = inner_map.entry((unique_pending_id, *key)).or_insert((*tag, Hash::get_zero_value()));
        entry.0 = *tag;
        Ok(())
    }
}


#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseZeroIdMerkleReader<Hash, Hasher, ZIM_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_select_zero_id_merkle_node_max_checkpoint(
        &self,
        table: &ZIM_TID,
        max_checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> Result<Hash> {
        let hash = self.zero_id_merkle_tables.get(table)
                    .and_then(|inner_map| inner_map.get(key).map(|v| v.clone()))
                    .and_then(|version_map| version_map.range(..=max_checkpoint_id).next_back().map(|(_, &h)| h))
                    .unwrap_or_else(|| Hasher::get_zero_hash(64 - key.level as usize)); // Assuming max height 64
        Ok(hash)
    }

    async fn db_select_many_zero_id_merkle_nodes_max_checkpoint(
        &self,
        table: &ZIM_TID,
        max_checkpoint_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> Result<Vec<Hash>> {
        let mut results = Vec::with_capacity(keys.len());
        if let Some(inner_map) = self.zero_id_merkle_tables.get(table) {
            for key in keys {
                let hash = inner_map.get(key)
                    .and_then(|version_map| version_map.range(..=max_checkpoint_id).next_back().map(|(_, &h)| h))
                    .unwrap_or_else(|| Hasher::get_zero_hash(64 - key.level as usize));
                results.push(hash);
            }
        } else {
            for key in keys {
                results.push(Hasher::get_zero_hash(64 - key.level as usize));
            }
        }
        Ok(results)
    }
}

#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseZeroIdMerkleWriter<Hash, Hasher, ZIM_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_insert_zero_id_merkle_node(
        &self,
        table: &ZIM_TID,
        checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
        value: &Hash,
    ) -> Result<()> {
        self.zero_id_merkle_tables.entry(table.clone()).or_default()
            .entry(*key).or_default().insert(checkpoint_id, *value);
        Ok(())
    }

    async fn db_set_zero_id_merkle_nodes_batch(
        &self,
        table: &ZIM_TID,
        checkpoint_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> Result<()> {
        let inner_map = self.zero_id_merkle_tables.entry(table.clone()).or_default();
        for node in nodes {
            inner_map.entry(node.key).or_default().insert(checkpoint_id, node.value);
        }
        Ok(())
    }
    async fn db_set_zero_id_merkle_nodes_from_fast_serialized(
        &self,
        table: &ZIM_TID,
        checkpoint_id: u64,
        nodes: &[u8],
    ) -> anyhow::Result<()> {
        todo!("not implemented");
    }
}


#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, DIM_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_select_double_id_merkle_node_max_checkpoint(
        &self,
        table: &DIM_TID,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> Result<Hash> {
        let composite_key = (tree_id, tree_sub_id, key);
        let hash = self.double_id_merkle_tables.get(table)
            .and_then(|inner_map| inner_map.get(&composite_key).map(|v| v.clone()))
            .and_then(|version_map| version_map.range(..=checkpoint_id).next_back().map(|(_, &h)| h))
            .unwrap_or_else(|| Hasher::get_zero_hash(tree_height as usize - key.level as usize));
        Ok(hash)
    }

    async fn db_select_many_double_id_merkle_nodes_max_checkpoint(
        &self,
        table: &DIM_TID,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> Result<Vec<Hash>> {
        let mut results = Vec::with_capacity(keys.len());
        if let Some(inner_map) = self.double_id_merkle_tables.get(table) {
            for &key in keys {
                let composite_key = (tree_id, tree_sub_id, key);
                let hash = inner_map.get(&composite_key)
                    .and_then(|version_map| version_map.range(..=max_checkpoint_id).next_back().map(|(_, &h)| h))
                    .unwrap_or_else(|| Hasher::get_zero_hash(tree_height as usize - key.level as usize));
                results.push(hash);
            }
        } else {
            for &key in keys {
                results.push(Hasher::get_zero_hash(tree_height as usize - key.level as usize));
            }
        }
        Ok(results)
    }
}

#[async_trait]
impl<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
    CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, DIM_TID>
    for InMemoryStore<Hash, Hasher, BM_TID, BU_TID, U64_TID, SI_TID, DI_TID, KIV_TID, SIM_TID, DIM_TID, ZIM_TID, TT_TID>
where
    Hash: QDBHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BM_TID: TIDBase,
    BU_TID: TIDBase,
    U64_TID: TIDBase,
    SI_TID: TIDBase,
    DI_TID: TIDBase,
    KIV_TID: TIDBase,
    SIM_TID: TIDBase,
    DIM_TID: TIDBase,
    ZIM_TID: TIDBase,
    TT_TID: TIDBase,
{
    async fn db_insert_double_id_merkle_node(
        &self,
        table: &DIM_TID,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        key: SimpleMerkleNodeKey,
        value: &Hash,
    ) -> Result<()> {
        let inner_map = self.double_id_merkle_tables.entry(table.clone()).or_default();
        let composite_key = (tree_id, tree_sub_id, key);
        inner_map.entry(composite_key).or_default().insert(checkpoint_id, *value);
        Ok(())
    }

    async fn db_set_double_id_merkle_nodes_batch(
        &self,
        table: &DIM_TID,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> Result<()> {
        let inner_map = self.double_id_merkle_tables.entry(table.clone()).or_default();
        for node in nodes {
            let composite_key = (tree_id, tree_sub_id, node.key);
            inner_map.entry(composite_key).or_default().insert(checkpoint_id, node.value);
        }
        Ok(())
    }

    async fn db_set_double_id_merkle_nodes_from_fast_serialized(
        &self,
        table: &DIM_TID,
        checkpoint_id: u64,
        nodes: &[u8],
    ) -> anyhow::Result<()> {
        todo!("not implemented");
    }
}

#[cfg(test)]
mod tests {
    use crate::gv1::InMemoryDb;

    use super::*;
    use bincode::de;
    use parth_core::data::{hash::hash256::Hash256, serializable::{QPDSerializable, QPDSerializableFixed}};
    use parth_crypto::hash::sha256::CoreSha256Hasher;
    use serde::{Deserialize, Serialize};
    use std::{convert::TryInto, sync::Arc};
    use tokio;
    type TestHash = Hash256;

    type TestHasher = CoreSha256Hasher;


    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
    struct TestValue {
        data: String,
        number: u32,
    }

    // For simplicity, we'll use a String as the table identifier in all tests.
    type TestTableId = String;

    // The concrete DB type for our tests
    type TestDb = InMemoryDb<
        TestHash,
        TestHasher,
        TestTableId,
        TestTableId,
        TestTableId,
        TestTableId,
        TestTableId,
        TestTableId,
        TestTableId,
        TestTableId,
        TestTableId,
        TestTableId,
    >;

    // =================================================================================
    // Test Cases
    // =================================================================================

    #[tokio::test]
    async fn test_kiv_store() {
        let db = TestDb::default();
        let table = "test_kiv".to_string();
        let value1 = TestValue {
            data: "hello".to_string(),
            number: 42,
        };
        let value2 = TestValue {
            data: "world".to_string(),
            number: 100,
        };

        // Insert and select one
        db.db_insert_one_kiv(&table, 1, &value1).await.unwrap();
        let selected: Option<TestValue> = db.db_select_one_kiv_value(&table, 1).await.unwrap();
        assert_eq!(selected, Some(value1.clone()));
        assert_eq!(db.db_select_one_kiv_value::<TestValue>(&table, 99).await.unwrap(), None);
        
        // Insert many and select many
        let rows = vec![
            QDatabaseKeyIdValueTableRow { obj_id: 2, value: value2.clone() },
            QDatabaseKeyIdValueTableRow { obj_id: 3, value: value1.clone() },
        ];
        db.db_insert_many_kivs(&table, &rows).await.unwrap();
        
        let selected_many: Vec<Option<TestValue>> = db.db_select_many_kiv_values(&table, &[1, 3, 99, 2]).await.unwrap();
        assert_eq!(selected_many, vec![Some(value1.clone()), Some(value1.clone()), None, Some(value2.clone())]);

        // Select all
        let all_rows = db.db_select_all_kiv::<TestValue>(&table).await.unwrap();
        assert_eq!(all_rows.len(), 3);
    }
    
    #[tokio::test]
    async fn test_u64_store() {
        let db = TestDb::default();
        let table = "test_u64".to_string();
        
        // Set and get
        db.db_set_u64_value(&table, 1, 1000).await.unwrap();
        assert_eq!(db.db_select_u64_value(&table, 1).await.unwrap(), Some(1000));
        
        // Increment
        let new_val = db.db_inc_counter(&table, 1, 50).await.unwrap();
        assert_eq!(new_val, 1050);
        assert_eq!(db.db_select_u64_value(&table, 1).await.unwrap(), Some(1050));
        
        // Decrement
        let new_val_decr = db.db_inc_counter(&table, 1, -100).await.unwrap();
        assert_eq!(new_val_decr, 950);

        // Increment non-existent
        let new_val_2 = db.db_inc_counter(&table, 2, 10).await.unwrap();
        assert_eq!(new_val_2, 10);
        assert_eq!(db.db_select_u64_value(&table, 2).await.unwrap(), Some(10));
    }
    
    #[tokio::test]
    async fn test_bidirectional_mapping_store() {
        let db = TestDb::default();
        let table = "test_bidi".to_string();

        #[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
        struct TestA {
            id: u64,
        }
        let kstr_rep_0 = Hash256::rand();
        let kstr_rep_1 = Hash256::rand();

        db.db_insert_pair(&table, 10u64, 20u64).await.unwrap();
        db.db_insert_pair(&table, kstr_rep_0, kstr_rep_1).await.unwrap();
        
        // Select by k1
        assert_eq!(db.db_select_one_by_k1::<u64, u64>(&table, &10).await.unwrap(), Some(20));
        assert_eq!(db.db_select_one_by_k1::<_, _>(&table, &kstr_rep_0).await.unwrap(), Some(kstr_rep_1));

        // Select by k2
        assert_eq!(db.db_select_one_by_k2::<u64, u64>(&table, &20).await.unwrap(), Some(10));
        assert_eq!(db.db_select_one_by_k2::<_, _>(&table, &kstr_rep_1).await.unwrap(), Some(kstr_rep_0));
        
        // Select non-existent
        assert_eq!(db.db_select_one_by_k1::<u64, u64>(&table, &99).await.unwrap(), None);
    }
    
    #[tokio::test]
    async fn test_single_id_checkpointed_store() {
        let db = TestDb::default();
        let table = "test_single_cp".to_string();
        let val1 = TestValue { data: "version 1".into(), number: 1 };
        let val2 = TestValue { data: "version 2".into(), number: 2 };

        db.db_insert_one_single_checkpointed_object(&table, 1, 10, &val1).await.unwrap();
        db.db_insert_one_single_checkpointed_object(&table, 1, 20, &val2).await.unwrap();
        
        // Query before first checkpoint
        assert_eq!(db.db_select_one_single_checkpointed_object_value::<TestValue>(&table, 1, 9).await.unwrap(), None);
        
        // Query at first checkpoint
        assert_eq!(db.db_select_one_single_checkpointed_object_value::<TestValue>(&table, 1, 10).await.unwrap(), Some(val1.clone()));

        // Query between checkpoints
        assert_eq!(db.db_select_one_single_checkpointed_object_value::<TestValue>(&table, 1, 15).await.unwrap(), Some(val1.clone()));

        // Query at second checkpoint
        assert_eq!(db.db_select_one_single_checkpointed_object_value::<TestValue>(&table, 1, 20).await.unwrap(), Some(val2.clone()));
        
        // Query far in the future
        assert_eq!(db.db_select_one_single_checkpointed_object_value::<TestValue>(&table, 1, 100).await.unwrap(), Some(val2.clone()));

        // Query non-existent key
        assert_eq!(db.db_select_one_single_checkpointed_object_value::<TestValue>(&table, 99, 100).await.unwrap(), None);

        // Test select with ids
        let row: QDatabaseSingleIdTableRow<TestValue> = db.db_select_one_single_checkpointed_object_value_and_ids(&table, 1, 15).await.unwrap().unwrap();
        assert_eq!(row.obj_id, 1);
        assert_eq!(row.checkpoint_id, 10);
        assert_eq!(row.value, val1);
    }

    #[tokio::test]
    async fn test_double_id_checkpointed_store() {
        let db = TestDb::default();
        let table = "test_double_cp".to_string();
        let val1 = TestValue { data: "double v1".into(), number: 1 };
        let val2 = TestValue { data: "double v2".into(), number: 2 };

        db.db_insert_one_double_checkpointed_object(&table, 1, 2, 10, &val1).await.unwrap();
        db.db_insert_one_double_checkpointed_object(&table, 1, 2, 20, &val2).await.unwrap();
        
        // Query between checkpoints
        let selected: Option<TestValue> = db.db_select_one_double_checkpointed_object_value(&table, 1, 2, 15).await.unwrap();
        assert_eq!(selected, Some(val1.clone()));

        // Query at second checkpoint
        let selected2: Option<TestValue> = db.db_select_one_double_checkpointed_object_value(&table, 1, 2, 100).await.unwrap();
        assert_eq!(selected2, Some(val2.clone()));

        // Query wrong secondary id
        let selected3: Option<TestValue> = db.db_select_one_double_checkpointed_object_value(&table, 1, 99, 100).await.unwrap();
        assert_eq!(selected3, None);
    }

    #[tokio::test]
    async fn test_single_id_merkle_store() {
        let db = TestDb::default();
        let table = "test_single_merkle".to_string();
        let tree_id = 1;
        let tree_height = 8;
        let key = SimpleMerkleNodeKey::new(1, 1); // Level 1, Index 1
        let hash1 = TestHash::rand();
        let hash2 = TestHash::rand();

        db.db_insert_single_id_merkle_node(&table, 10, tree_id, key, &hash1).await.unwrap();
        db.db_insert_single_id_merkle_node(&table, 20, tree_id, key, &hash2).await.unwrap();

        // Query before any version exists
        let zero_hash = TestHasher::get_zero_hash(tree_height as usize - key.level as usize);
        assert_eq!(db.db_select_single_id_merkle_node_max_checkpoint(&table, 5, tree_id, tree_height, key).await.unwrap(), zero_hash);

        // Query at first version
        assert_eq!(db.db_select_single_id_merkle_node_max_checkpoint(&table, 15, tree_id, tree_height, key).await.unwrap(), hash1);

        // Query at second version
        assert_eq!(db.db_select_single_id_merkle_node_max_checkpoint(&table, 25, tree_id, tree_height, key).await.unwrap(), hash2);
    }

    #[tokio::test]
    async fn test_concurrency_u64_store() {
        let db = Arc::new(TestDb::default());
        let table = "concurrent_u64".to_string();
        let counter_id = 1;
        let num_tasks = 100;
        let increments_per_task = 1000;
        
        let mut handles = vec![];
        
        for _ in 0..num_tasks {
            let db_clone = db.clone();
            let table_clone = table.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..increments_per_task {
                    db_clone.db_inc_counter(&table_clone, counter_id, 1).await.unwrap();
                }
            }));
        }
        
        futures::future::join_all(handles).await;
        
        let final_value = db.db_select_u64_value(&table, counter_id).await.unwrap().unwrap();
        assert_eq!(final_value, (num_tasks * increments_per_task) as u64);
    }
    
    #[tokio::test]
    async fn test_concurrency_checkpointed_store() {
        let db = Arc::new(TestDb::default());
        let table = "concurrent_checkpointed".to_string();
        let num_tasks = 50;

        let mut handles = vec![];

        // Writer tasks
        for i in 0..num_tasks {
            let db_clone = db.clone();
            let table_clone = table.clone();
            handles.push(tokio::spawn(async move {
                let val = TestValue { data: format!("data_{}", i), number: i as u32 };
                // Each task writes to a unique key and checkpoint to avoid logical races,
                // but they all contend for locks on the underlying DashMap shards.
                db_clone.db_insert_one_single_checkpointed_object(&table_clone, i as u64, i as u64, &val).await.unwrap();
            }));
        }

        futures::future::join_all(handles).await;
        
        let mut reader_handles = vec![];
        
        // Reader tasks
        for i in 0..num_tasks {
            let db_clone = db.clone();
            let table_clone = table.clone();
            reader_handles.push(tokio::spawn(async move {
                let expected_val = TestValue { data: format!("data_{}", i), number: i as u32 };
                
                // Read at a checkpoint that should resolve this task's write
                let selected = db_clone.db_select_one_single_checkpointed_object_value::<TestValue>(&table_clone, i as u64, i as u64).await.unwrap();
                
                // Read at a checkpoint before this task's write
                let selected_none = db_clone.db_select_one_single_checkpointed_object_value::<TestValue>(&table_clone, i as u64, (i as u64).saturating_sub(1) as u64).await.unwrap();
                
                assert_eq!(selected, Some(expected_val));
                assert_eq!(selected_none, None);
            }));
        }

        futures::future::join_all(reader_handles).await;
    }
}