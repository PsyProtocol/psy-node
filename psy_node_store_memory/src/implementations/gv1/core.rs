//https://aistudio.google.com/prompts/1nX4AInNPB95SSRStlCvRIqs0AEoVTgWN?_gl=1*m14tst*_ga*MTQ4NDUwODIzMi4xNzQyNjUzNzMx*_ga_P1DBVKWT6V*MTc0MjY1MzczMC4xLjAuMTc0MjY1MzczMy41Ny4wLjk4OTg3NDExNg..

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
    protocol::core_types::QHashBase,
};
use parking_lot::RwLock;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::BTreeMap,
    fmt::Debug,
    future,
    hash::Hash,
    marker::PhantomData,
    sync::Arc,
};

use crate::utils::TIDBase;

use psy_node_core::store::traits::core_db::{
    CoreDatabaseBidirectionalMappingReader, CoreDatabaseBidirectionalMappingWriter, CoreDatabaseBidirectionalU64U128MappingReader, CoreDatabaseBidirectionalU64U128MappingWriter, CoreDatabaseDoubleIdCheckpointedReader, CoreDatabaseDoubleIdCheckpointedWriter, CoreDatabaseDoubleIdMerkleReader, CoreDatabaseDoubleIdMerkleWriter, CoreDatabaseKivReader, CoreDatabaseKivWriter, CoreDatabaseSingleIdCheckpointedReader, CoreDatabaseSingleIdCheckpointedWriter, CoreDatabaseSingleIdMerkleReader, CoreDatabaseSingleIdMerkleWriter, CoreDatabaseStore, CoreDatabaseTagTreeReader, CoreDatabaseTagTreeStore, CoreDatabaseTagTreeWriter, CoreDatabaseU64Reader, CoreDatabaseU64Writer, CoreDatabaseZeroIdMerkleReader, CoreDatabaseZeroIdMerkleWriter
};


// A type alias for a collection of versioned data, keyed by checkpoint ID.
// The BTreeMap is chosen for its efficient range queries, which are essential for finding
// the latest version up to a specific checkpoint.
type VersionedData<V> = Arc<RwLock<BTreeMap<u64, V>>>;

/// A helper function to serialize a value into a byte vector using bincode.
fn serialize_value<V: Serialize>(value: &V) -> anyhow::Result<Vec<u8>> {
    bincode::serialize(value).map_err(anyhow::Error::from)
}

/// A helper function to deserialize a byte slice into a value using bincode.
fn deserialize_value<V: CoreDatabaseValueDeserialize>(data: &[u8]) -> anyhow::Result<V> {
    bincode::deserialize(data).map_err(anyhow::Error::from)
}

#[derive(Debug, Clone)]
pub struct InMemoryDb<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BiDirectionalMappingTableIdentifier: TIDBase + Debug,
    BiDirectionalU64U128MappingTableIdentifier: TIDBase,
    U64TableIdentifier: TIDBase,
    SingleIdTableIdentifier: TIDBase,
    DoubleIdTableIdentifier: TIDBase,
    KivTableIdentifier: TIDBase,
    SingleIdMerkleTableIdentifier: TIDBase,
    DoubleIdMerkleTableIdentifier: TIDBase,
    ZeroIdMerkleTableIdentifier: TIDBase,
    TagTreeTableIdentifier: TIDBase,
> {
    // Bidirectional Mapping Stores
    bi_map_k1_k2: Arc<DashMap<BiDirectionalMappingTableIdentifier, Arc<DashMap<Vec<u8>, Vec<u8>>>>>,
    bi_map_k2_k1: Arc<DashMap<BiDirectionalMappingTableIdentifier, Arc<DashMap<Vec<u8>, Vec<u8>>>>>,
    bi_u64_u128_k1_k2: Arc<DashMap<BiDirectionalU64U128MappingTableIdentifier, Arc<DashMap<u64, u128>>>>,
    bi_u64_u128_k2_k1: Arc<DashMap<BiDirectionalU64U128MappingTableIdentifier, Arc<DashMap<u128, u64>>>>,

    // Simple U64 Store
    u64_store: Arc<DashMap<U64TableIdentifier, Arc<DashMap<u64, u64>>>>,

    // Checkpointed Stores
    single_id_checkpointed_store: Arc<DashMap<SingleIdTableIdentifier, Arc<DashMap<u64, VersionedData<Vec<u8>>>>>>,
    double_id_checkpointed_store: Arc<DashMap<DoubleIdTableIdentifier, Arc<DashMap<QDoubleIdKey, VersionedData<Vec<u8>>>>>>,

    // Key-ID-Value Store
    kiv_store: Arc<DashMap<KivTableIdentifier, Arc<DashMap<u64, Vec<u8>>>>>,

    // Merkle Tree Stores (all are checkpointed)
    single_id_merkle_store: Arc<DashMap<SingleIdMerkleTableIdentifier, Arc<DashMap<(u64, SimpleMerkleNodeKey), VersionedData<Hash>>>>>,
    double_id_merkle_store: Arc<DashMap<DoubleIdMerkleTableIdentifier, Arc<DashMap<(u64, u64, SimpleMerkleNodeKey), VersionedData<Hash>>>>>,
    zero_id_merkle_store: Arc<DashMap<ZeroIdMerkleTableIdentifier, Arc<DashMap<SimpleMerkleNodeKey, VersionedData<Hash>>>>>,
    
    // Tag Tree Store (not checkpointed)
    tag_tree_tags: Arc<DashMap<TagTreeTableIdentifier, Arc<DashMap<(u64, SimpleMerkleNodeKey), Hash>>>>,
    tag_tree_values: Arc<DashMap<TagTreeTableIdentifier, Arc<DashMap<(u64, SimpleMerkleNodeKey), Hash>>>>,

    _phantom: PhantomData<(Hash, Hasher)>,
}

impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> Default for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    fn default() -> Self {
        Self {
            bi_map_k1_k2: Arc::new(DashMap::new()),
            bi_map_k2_k1: Arc::new(DashMap::new()),
            bi_u64_u128_k1_k2: Arc::new(DashMap::new()),
            bi_u64_u128_k2_k1: Arc::new(DashMap::new()),
            u64_store: Arc::new(DashMap::new()),
            single_id_checkpointed_store: Arc::new(DashMap::new()),
            double_id_checkpointed_store: Arc::new(DashMap::new()),
            kiv_store: Arc::new(DashMap::new()),
            single_id_merkle_store: Arc::new(DashMap::new()),
            double_id_merkle_store: Arc::new(DashMap::new()),
            zero_id_merkle_store: Arc::new(DashMap::new()),
            tag_tree_tags: Arc::new(DashMap::new()),
            tag_tree_values: Arc::new(DashMap::new()),
            _phantom: PhantomData,
        }
    }
}


// Generic helper function to get or create a table from a store
fn get_or_create_table<TID: Eq + Hash + Clone, Table>(
    store: &DashMap<TID, Arc<Table>>,
    table_id: &TID,
) -> Arc<Table>
where
    Table: Default,
{
    if let Some(table) = store.get(table_id) {
        return table.clone();
    }
    let table = Arc::new(Table::default());
    store.insert(table_id.clone(), table.clone());
    table
}

// Helper to find the latest version in a versioned BTreeMap
fn find_latest_version<V: Clone>(version_map: &BTreeMap<u64, V>, max_checkpoint_id: u64) -> Option<(u64, V)> {
    version_map
        .range(..=max_checkpoint_id)
        .next_back()
        .map(|(k, v)| (*k, v.clone()))
}

// ---------------------------------------------------------------------------------
//
//               CoreDatabaseBidirectionalMappingStore Implementation
//
// ---------------------------------------------------------------------------------

#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseBidirectionalMappingReader<BMID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_select_one_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BMID,
        k1: &K1,
    ) -> anyhow::Result<Option<K2>> {
        let k1_bytes = k1.to_bytes()?;
        let table_store = get_or_create_table(&self.bi_map_k1_k2, table);
        
        if let Some(k2_bytes) = table_store.get(&k1_bytes) {
            let k2 = K2::from_bytes(&k2_bytes)?;
            return future::ready(Ok(Some(k2))).await;
        }
        future::ready(Ok(None)).await
    }

    async fn db_select_one_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BMID,
        k2: &K2,
    ) -> anyhow::Result<Option<K1>> {
        let k2_bytes = k2.to_bytes()?;
        let table_store = get_or_create_table(&self.bi_map_k2_k1, table);

        if let Some(k1_bytes) = table_store.get(&k2_bytes) {
            let k1 = K1::from_bytes(&k1_bytes)?;
            return future::ready(Ok(Some(k1))).await;
        }
        future::ready(Ok(None)).await
    }

    async fn db_select_many_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BMID,
        k1s: &[K1],
    ) -> anyhow::Result<Vec<Option<K2>>> {
        let table_store = get_or_create_table(&self.bi_map_k1_k2, table);
        let mut results = Vec::with_capacity(k1s.len());
        for k1 in k1s {
            let k1_bytes = k1.to_bytes()?;
            let result = table_store.get(&k1_bytes)
                .map(|k2_bytes| K2::from_bytes(&k2_bytes))
                .transpose()?;
            results.push(result);
        }
        Ok(results)
    }

    async fn db_select_many_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BMID,
        k2s: &[K2],
    ) -> anyhow::Result<Vec<Option<K1>>> {
        let table_store = get_or_create_table(&self.bi_map_k2_k1, table);
        let mut results = Vec::with_capacity(k2s.len());
        for k2 in k2s {
            let k2_bytes = k2.to_bytes()?;
            let result = table_store.get(&k2_bytes)
                .map(|k1_bytes| K1::from_bytes(&k1_bytes))
                .transpose()?;
            results.push(result);
        }
        Ok(results)
    }

    async fn db_select_many_pairs_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BMID,
        k1s: &[K1],
    ) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        let table_store = get_or_create_table(&self.bi_map_k1_k2, table);
        let mut results = Vec::new();
        for k1 in k1s {
            let k1_bytes = k1.to_bytes()?;
            if let Some(k2_bytes) = table_store.get(&k1_bytes) {
                let k2 = K2::from_bytes(&k2_bytes)?;
                results.push(BiDirectionalMappingRow { k1: k1.clone(), k2 });
            }
        }
        Ok(results)
    }

    async fn db_select_many_pairs_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BMID,
        k2s: &[K2],
    ) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        let table_store = get_or_create_table(&self.bi_map_k2_k1, table);
        let mut results = Vec::new();
        for k2 in k2s {
            let k2_bytes = k2.to_bytes()?;
            if let Some(k1_bytes) = table_store.get(&k2_bytes) {
                let k1 = K1::from_bytes(&k1_bytes)?;
                results.push(BiDirectionalMappingRow { k1, k2: k2.clone() });
            }
        }
        Ok(results)
    }

    async fn db_select_all_pairs_from_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BMID,
        start_k1: Option<K1>,
        max_count: usize,
    ) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        let k1_k2_table = get_or_create_table(&self.bi_map_k1_k2, table);
        let start_bytes = match start_k1 {
            Some(k1) => k1.to_bytes()?,
            None => vec![],
        };

        let mut results = Vec::with_capacity(max_count);
        // This is a full scan, which can be slow. DashMap is not ordered.
        // We'll sort keys to provide a stable-enough ordering.
        let mut keys: Vec<Vec<u8>> = k1_k2_table.iter().map(|e| e.key().clone()).collect();
        keys.sort();

        for k1_bytes in keys.into_iter().filter(|k| k >= &start_bytes) {
            if results.len() >= max_count {
                break;
            }
            if let Some(k2_bytes) = k1_k2_table.get(&k1_bytes) {
                let k1 = K1::from_bytes(&k1_bytes)?;
                let k2 = K2::from_bytes(&k2_bytes)?;
                results.push(BiDirectionalMappingRow { k1, k2 });
            }
        }
        Ok(results)
    }
}


#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseBidirectionalMappingWriter<BMID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_insert_pair_ref<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BMID,
        k1: &K1,
        k2: &K2,
    ) -> anyhow::Result<()> {
        let k1_bytes = k1.to_bytes()?;
        let k2_bytes = k2.to_bytes()?;

        let k1_k2_table = get_or_create_table(&self.bi_map_k1_k2, table);
        let k2_k1_table = get_or_create_table(&self.bi_map_k2_k1, table);

        k1_k2_table.insert(k1_bytes, k2_bytes.clone());
        k2_k1_table.insert(k2_bytes, k1.to_bytes()?);

        Ok(())
    }

    async fn db_insert_pair<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BMID,
        k1: K1,
        k2: K2,
    ) -> anyhow::Result<()> {
        self.db_insert_pair_ref(table, &k1, &k2).await
    }

    async fn db_insert_pairs<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BMID,
        keys: &[BiDirectionalMappingRow<K1, K2>],
    ) -> anyhow::Result<()> {
        let k1_k2_table = get_or_create_table(&self.bi_map_k1_k2, table);
        let k2_k1_table = get_or_create_table(&self.bi_map_k2_k1, table);

        for row in keys {
            let k1_bytes = row.k1.to_bytes()?;
            let k2_bytes = row.k2.to_bytes()?;
            k1_k2_table.insert(k1_bytes, k2_bytes.clone());
            k2_k1_table.insert(k2_bytes, row.k1.to_bytes()?);
        }

        Ok(())
    }
}


// ---------------------------------------------------------------------------------
//
//           CoreDatabaseBidirectionalU64U128MappingStore Implementation
//
// ---------------------------------------------------------------------------------


#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseBidirectionalU64U128MappingReader<BMUID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_select_one_u128_value_by_u64(&self, table: &BMUID, key: u64) -> anyhow::Result<Option<u128>> {
        let k1_k2_table = get_or_create_table(&self.bi_u64_u128_k1_k2, table);
        Ok(k1_k2_table.get(&key).map(|v| *v))
    }

    async fn db_select_one_u64_key_by_u128(&self, table: &BMUID, value: u128) -> anyhow::Result<Option<u64>> {
        let k2_k1_table = get_or_create_table(&self.bi_u64_u128_k2_k1, table);
        Ok(k2_k1_table.get(&value).map(|v| *v))
    }

    async fn db_select_many_u128_values_by_u64s(&self, table: &BMUID, keys: &[u64]) -> anyhow::Result<Vec<Option<u128>>> {
        let k1_k2_table = get_or_create_table(&self.bi_u64_u128_k1_k2, table);
        let results = keys.iter().map(|k| k1_k2_table.get(k).map(|v| *v)).collect();
        Ok(results)
    }

    async fn db_select_many_u64_keys_by_u128s(&self, table: &BMUID, values: &[u128]) -> anyhow::Result<Vec<Option<u64>>> {
        let k2_k1_table = get_or_create_table(&self.bi_u64_u128_k2_k1, table);
        let results = values.iter().map(|v| k2_k1_table.get(v).map(|k| *k)).collect();
        Ok(results)
    }
}

#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseBidirectionalU64U128MappingWriter<BMUID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_insert_u64_u128_mapping_pair(&self, table: &BMUID, k1: u64, k2: u128) -> anyhow::Result<()> {
        let k1_k2_table = get_or_create_table(&self.bi_u64_u128_k1_k2, table);
        let k2_k1_table = get_or_create_table(&self.bi_u64_u128_k2_k1, table);
        k1_k2_table.insert(k1, k2);
        k2_k1_table.insert(k2, k1);
        Ok(())
    }

    async fn db_insert_u64_u128_mapping_pairs(&self, table: &BMUID, keys: &[BiDirectionalMappingRow<u64, u128>]) -> anyhow::Result<()> {
        let k1_k2_table = get_or_create_table(&self.bi_u64_u128_k1_k2, table);
        let k2_k1_table = get_or_create_table(&self.bi_u64_u128_k2_k1, table);
        for row in keys {
            k1_k2_table.insert(row.k1, row.k2);
            k2_k1_table.insert(row.k2, row.k1);
        }
        Ok(())
    }
}


// ---------------------------------------------------------------------------------
//
//                       CoreDatabaseU64Store Implementation
//
// ---------------------------------------------------------------------------------

#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseU64Reader<UID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_select_u64_value(&self, table: &UID, obj_id: u64) -> anyhow::Result<Option<u64>> {
        let table_store = get_or_create_table(&self.u64_store, table);
        Ok(table_store.get(&obj_id).map(|v| *v))
    }

    async fn db_select_u64_values(&self, table: &UID, obj_ids: &[u64]) -> anyhow::Result<Vec<Option<u64>>> {
        let table_store = get_or_create_table(&self.u64_store, table);
        Ok(obj_ids.iter().map(|id| table_store.get(id).map(|v| *v)).collect())
    }
}


#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseU64Writer<UID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_inc_counter(&self, table: &UID, obj_id: u64, amount: i64) -> anyhow::Result<u64> {
        let table_store = get_or_create_table(&self.u64_store, table);
        let new_val = table_store.entry(obj_id)
            .and_modify(|v| {
                if amount >= 0 {
                    *v = v.saturating_add(amount as u64);
                } else {
                    *v = v.saturating_sub(amount.abs() as u64);
                }
            })
            .or_insert_with(|| if amount >= 0 { amount as u64 } else { 0 })
            .value()
            .clone();
        Ok(new_val)
    }

    async fn db_set_u64_value(&self, table: &UID, obj_id: u64, value: u64) -> anyhow::Result<()> {
        let table_store = get_or_create_table(&self.u64_store, table);
        table_store.insert(obj_id, value);
        Ok(())
    }

    async fn db_set_many_u64_values(&self, table: &UID, rows: &[QPDPair<u64, u64>]) -> anyhow::Result<()> {
        let table_store = get_or_create_table(&self.u64_store, table);
        for row in rows {
            table_store.insert(row.key, row.value);
        }
        Ok(())
    }
}


// ---------------------------------------------------------------------------------
//
//              CoreDatabaseSingleIdCheckpointedStore Implementation
//
// ---------------------------------------------------------------------------------

#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseSingleIdCheckpointedReader<SID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_select_one_single_checkpointed_object_value<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &SID,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<V>> {
        let table_store = get_or_create_table(&self.single_id_checkpointed_store, table);
        if let Some(version_data) = table_store.get(&obj_id) {
            let versions = version_data.read();
            if let Some((_, value_bytes)) = find_latest_version(&versions, max_checkpoint_id) {
                return Ok(Some(deserialize_value(&value_bytes)?));
            }
        }
        Ok(None)
    }
    
    async fn db_select_one_single_checkpointed_object_value_and_ids<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &SID,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<QDatabaseSingleIdTableRow<V>>> {
        let table_store = get_or_create_table(&self.single_id_checkpointed_store, table);
        if let Some(version_data) = table_store.get(&obj_id) {
            let versions = version_data.read();
            if let Some((checkpoint_id, value_bytes)) = find_latest_version(&versions, max_checkpoint_id) {
                let value = deserialize_value(&value_bytes)?;
                return Ok(Some(QDatabaseSingleIdTableRow { obj_id, checkpoint_id, value }));
            }
        }
        Ok(None)
    }
    
    async fn db_select_one_single_checkpointed_object_value_and_ids_t<
        V: CoreDatabaseValueDeserialize,
        R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &SID,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<R>> {
        if let Some(row) = self.db_select_one_single_checkpointed_object_value_and_ids(table, obj_id, max_checkpoint_id).await? {
            return Ok(Some(R::create_from_single_row(row.obj_id, row.checkpoint_id, row.value)));
        }
        Ok(None)
    }
    
    async fn db_select_all_single_checkpointed_object<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &SID,
    ) -> anyhow::Result<Vec<QDatabaseSingleIdTableRow<V>>> {
        let table_store = get_or_create_table(&self.single_id_checkpointed_store, table);
        let mut results = Vec::new();
        for entry in table_store.iter() {
            let obj_id = *entry.key();
            let versions = entry.value().read();
            for (checkpoint_id, value_bytes) in versions.iter() {
                let value = deserialize_value(value_bytes)?;
                results.push(QDatabaseSingleIdTableRow {
                    obj_id,
                    checkpoint_id: *checkpoint_id,
                    value,
                });
            }
        }
        Ok(results)
    }

    async fn db_select_many_single_checkpointed_object_values<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &SID,
        obj_ids: &[u64],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<Option<V>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        for &obj_id in obj_ids {
            results.push(self.db_select_one_single_checkpointed_object_value(table, obj_id, max_checkpoint_id).await?);
        }
        Ok(results)
    }

    async fn db_select_many_single_checkpointed_object_keys_and_values<
        V: CoreDatabaseValueDeserialize,
        R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &SID,
        obj_ids: &[u64],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<R>> {
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
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseSingleIdCheckpointedWriter<SID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_insert_one_single_checkpointed_object<V: Serialize + Send + Sync>(
        &self,
        table: &SID,
        obj_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> anyhow::Result<()> {
        let table_store = get_or_create_table(&self.single_id_checkpointed_store, table);
        let value_bytes = serialize_value(value)?;

        let version_data = table_store.entry(obj_id).or_default().clone();
        version_data.write().insert(checkpoint_id, value_bytes);
        
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_object_rows<V: Serialize + Send + Sync>(
        &self,
        table: &SID,
        rows: &[QDatabaseSingleIdTableRow<V>],
    ) -> anyhow::Result<()> {
        for row in rows {
            self.db_insert_one_single_checkpointed_object(table, row.obj_id, row.checkpoint_id, &row.value).await?;
        }
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_object_rows_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseSingleIdTableRowLike<V> + Send + Sync,
    >(
        &self,
        table: &SID,
        rows: &[R],
    ) -> anyhow::Result<()> {
        for row in rows {
            self.db_insert_one_single_checkpointed_object(table, row.get_row_obj_id(), row.get_row_checkpoint_id(), row.get_row_value_ref()).await?;
        }
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_objects_at_checkpoint<V: Serialize + Send + Sync>(
        &self,
        table: &SID,
        checkpoint_id: u64,
        rows: &[QDatabaseSingleIdTableRowNoCheckpointId<V>],
    ) -> anyhow::Result<()> {
        for row in rows {
            self.db_insert_one_single_checkpointed_object(table, row.obj_id, checkpoint_id, &row.value).await?;
        }
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseSingleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &SID,
        checkpoint_id: u64,
        rows: &[R],
    ) -> anyhow::Result<()> {
        for row in rows {
            self.db_insert_one_single_checkpointed_object(table, row.get_row_obj_id(), checkpoint_id, row.get_row_value_ref()).await?;
        }
        Ok(())
    }
}


// ---------------------------------------------------------------------------------
//
//              CoreDatabaseDoubleIdCheckpointedStore Implementation
//
// ---------------------------------------------------------------------------------

#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseDoubleIdCheckpointedReader<DID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_select_one_double_checkpointed_object_value<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &DID,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<V>> {
        let key = QDoubleIdKey { obj_id, secondary_id };
        let table_store = get_or_create_table(&self.double_id_checkpointed_store, table);
        if let Some(version_data) = table_store.get(&key) {
            let versions = version_data.read();
            if let Some((_, value_bytes)) = find_latest_version(&versions, max_checkpoint_id) {
                return Ok(Some(deserialize_value(&value_bytes)?));
            }
        }
        Ok(None)
    }

    async fn db_select_one_double_checkpointed_object_value_and_ids<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &DID,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<QDatabaseDoubleIdTableRow<V>>> {
        let key = QDoubleIdKey { obj_id, secondary_id };
        let table_store = get_or_create_table(&self.double_id_checkpointed_store, table);
        if let Some(version_data) = table_store.get(&key) {
            let versions = version_data.read();
            if let Some((checkpoint_id, value_bytes)) = find_latest_version(&versions, max_checkpoint_id) {
                let value = deserialize_value(&value_bytes)?;
                return Ok(Some(QDatabaseDoubleIdTableRow { obj_id, secondary_id, checkpoint_id, value }));
            }
        }
        Ok(None)
    }
    
    async fn db_select_one_double_checkpointed_object_value_and_ids_t<
        V: CoreDatabaseValueDeserialize,
        R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &DID,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<R>> {
        if let Some(row) = self.db_select_one_double_checkpointed_object_value_and_ids(table, obj_id, secondary_id, max_checkpoint_id).await? {
            return Ok(Some(R::create_from_double_row(row.obj_id, row.secondary_id, row.checkpoint_id, row.value)));
        }
        Ok(None)
    }
    
    async fn db_select_all_double_checkpointed_object<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &DID,
    ) -> anyhow::Result<Vec<QDatabaseDoubleIdTableRow<V>>> {
        let table_store = get_or_create_table(&self.double_id_checkpointed_store, table);
        let mut results = Vec::new();
        for entry in table_store.iter() {
            let key = entry.key();
            let versions = entry.value().read();
            for (checkpoint_id, value_bytes) in versions.iter() {
                let value = deserialize_value(value_bytes)?;
                results.push(QDatabaseDoubleIdTableRow {
                    obj_id: key.obj_id,
                    secondary_id: key.secondary_id,
                    checkpoint_id: *checkpoint_id,
                    value,
                });
            }
        }
        Ok(results)
    }

    async fn db_select_many_double_checkpointed_object_values<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &DID,
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<Option<V>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        for key in obj_ids {
            results.push(self.db_select_one_double_checkpointed_object_value(table, key.obj_id, key.secondary_id, max_checkpoint_id).await?);
        }
        Ok(results)
    }

    async fn db_select_many_double_checkpointed_object_keys_and_values<
        V: CoreDatabaseValueDeserialize,
        R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &DID,
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<R>> {
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
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseDoubleIdCheckpointedWriter<DID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_insert_one_double_checkpointed_object<V: Serialize + Send + Sync>(
        &self,
        table: &DID,
        obj_id: u64,
        secondary_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> anyhow::Result<()> {
        let key = QDoubleIdKey { obj_id, secondary_id };
        let table_store = get_or_create_table(&self.double_id_checkpointed_store, table);
        let value_bytes = serialize_value(value)?;

        let version_data = table_store.entry(key).or_default().clone();
        version_data.write().insert(checkpoint_id, value_bytes);

        Ok(())
    }

    async fn db_insert_many_double_checkpointed_object_rows<V: Serialize + Send + Sync>(
        &self,
        table: &DID,
        rows: &[QDatabaseDoubleIdTableRow<V>],
    ) -> anyhow::Result<()> {
        for row in rows {
            self.db_insert_one_double_checkpointed_object(table, row.obj_id, row.secondary_id, row.checkpoint_id, &row.value).await?;
        }
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_object_rows_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseDoubleIdTableRowLike<V> + Send + Sync,
    >(
        &self,
        table: &DID,
        rows: &[R],
    ) -> anyhow::Result<()> {
        for row in rows {
            self.db_insert_one_double_checkpointed_object(table, row.get_row_obj_id(), row.get_row_secondary_id(), row.get_row_checkpoint_id(), row.get_row_value_ref()).await?;
        }
        Ok(())
    }
    
    async fn db_insert_many_double_checkpointed_objects_at_checkpoint<V: Serialize + Send + Sync>(
        &self,
        table: &DID,
        checkpoint_id: u64,
        rows: &[QDatabaseDoubleIdTableRowNoCheckpointId<V>],
    ) -> anyhow::Result<()> {
        for row in rows {
            self.db_insert_one_double_checkpointed_object(table, row.obj_id, row.secondary_id, checkpoint_id, &row.value).await?;
        }
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_objects_at_checkpoint_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseDoubleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &DID,
        checkpoint_id: u64,
        rows: &[R],
    ) -> anyhow::Result<()> {
        for row in rows {
            self.db_insert_one_double_checkpointed_object(table, row.get_row_obj_id(), row.get_row_secondary_id(), checkpoint_id, row.get_row_value_ref()).await?;
        }
        Ok(())
    }
}


// ---------------------------------------------------------------------------------
//
//                       CoreDatabaseKivStore Implementation
//
// ---------------------------------------------------------------------------------

#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseKivReader<KID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_select_one_kiv_value<V: CoreDatabaseValueDeserialize>(&self, table: &KID, obj_id: u64) -> anyhow::Result<Option<V>> {
        let table_store = get_or_create_table(&self.kiv_store, table);
        if let Some(value_bytes) = table_store.get(&obj_id) {
            return Ok(Some(deserialize_value(&value_bytes)?));
        }
        Ok(None)
    }

    async fn db_select_one_kiv_value_and_ids<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &KID,
        obj_id: u64,
    ) -> anyhow::Result<Option<QDatabaseKeyIdValueTableRow<V>>> {
        if let Some(value) = self.db_select_one_kiv_value(table, obj_id).await? {
            return Ok(Some(QDatabaseKeyIdValueTableRow { obj_id, value }));
        }
        Ok(None)
    }

    async fn db_select_one_kiv_value_and_ids_t<V: CoreDatabaseValueDeserialize, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(
        &self,
        table: &KID,
        obj_id: u64,
    ) -> anyhow::Result<Option<R>> {
        if let Some(value) = self.db_select_one_kiv_value(table, obj_id).await? {
            return Ok(Some(R::create_from_key_id_value_row(obj_id, value)));
        }
        Ok(None)
    }

    async fn db_select_all_kiv<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &KID,
    ) -> anyhow::Result<Vec<QDatabaseKeyIdValueTableRow<V>>> {
        let table_store = get_or_create_table(&self.kiv_store, table);
        let mut results = Vec::new();
        for entry in table_store.iter() {
            let value = deserialize_value(entry.value())?;
            results.push(QDatabaseKeyIdValueTableRow {
                obj_id: *entry.key(),
                value,
            });
        }
        Ok(results)
    }

    async fn db_select_many_kiv_values<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &KID,
        obj_ids: &[u64],
    ) -> anyhow::Result<Vec<Option<V>>> {
        let table_store = get_or_create_table(&self.kiv_store, table);
        let mut results = Vec::with_capacity(obj_ids.len());
        for &obj_id in obj_ids {
            let value = table_store.get(&obj_id)
                .map(|val_bytes| deserialize_value(&val_bytes))
                .transpose()?;
            results.push(value);
        }
        Ok(results)
    }

    async fn db_select_many_kiv_keys_and_values<V: CoreDatabaseValueDeserialize, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(
        &self,
        table: &KID,
        obj_ids: &[u64],
    ) -> anyhow::Result<Vec<R>> {
        let table_store = get_or_create_table(&self.kiv_store, table);
        let mut results = Vec::new();
        for &obj_id in obj_ids {
            if let Some(val_bytes) = table_store.get(&obj_id) {
                let value = deserialize_value(&val_bytes)?;
                results.push(R::create_from_key_id_value_row(obj_id, value));
            }
        }
        Ok(results)
    }
}


#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseKivWriter<KID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_insert_one_kiv<V: Serialize + Send + Sync>(&self, table: &KID, obj_id: u64, value: &V) -> anyhow::Result<()> {
        let table_store = get_or_create_table(&self.kiv_store, table);
        let value_bytes = serialize_value(value)?;
        table_store.insert(obj_id, value_bytes);
        Ok(())
    }

    async fn db_insert_many_kivs<V: Serialize + Send + Sync>(
        &self,
        table: &KID,
        rows: &[QDatabaseKeyIdValueTableRow<V>],
    ) -> anyhow::Result<()> {
        let table_store = get_or_create_table(&self.kiv_store, table);
        for row in rows {
            let value_bytes = serialize_value(&row.value)?;
            table_store.insert(row.obj_id, value_bytes);
        }
        Ok(())
    }

    async fn db_insert_many_kivs_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseKeyIdValueTableRowLike<V> + Send + Sync>(
        &self,
        table: &KID,
        rows: &[R],
    ) -> anyhow::Result<()> {
        let table_store = get_or_create_table(&self.kiv_store, table);
        for row in rows {
            let value_bytes = serialize_value(row.get_row_value_ref())?;
            table_store.insert(row.get_row_obj_id(), value_bytes);
        }
        Ok(())
    }
}


// ---------------------------------------------------------------------------------
//
//                 CoreDatabaseSingleIdMerkleStore Implementation
//
// ---------------------------------------------------------------------------------

#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseSingleIdMerkleReader<H, Hs, SMID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_select_single_id_merkle_node_max_checkpoint(
        &self,
        table: &SMID,
        checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<H> {
        let table_store = get_or_create_table(&self.single_id_merkle_store, table);
        let db_key = (tree_id, key);

        if let Some(version_data) = table_store.get(&db_key) {
            let versions = version_data.read();
            if let Some((_, hash)) = find_latest_version(&versions, checkpoint_id) {
                return Ok(hash);
            }
        }
        
        Ok(Hs::get_zero_hash(tree_height.saturating_sub(key.level) as usize))
    }

    async fn db_select_many_single_id_merkle_nodes_max_checkpoint(
        &self,
        table: &SMID,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<H>> {
        let mut results = Vec::with_capacity(keys.len());
        for &key in keys {
            results.push(self.db_select_single_id_merkle_node_max_checkpoint(table, max_checkpoint_id, tree_id, tree_height, key).await?);
        }
        Ok(results)
    }
}

#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseSingleIdMerkleWriter<H, Hs, SMID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_insert_single_id_merkle_node(
        &self,
        table: &SMID,
        checkpoint_id: u64,
        tree_id: u64,
        key: SimpleMerkleNodeKey,
        value: &H,
    ) -> anyhow::Result<()> {
        let table_store = get_or_create_table(&self.single_id_merkle_store, table);
        let db_key = (tree_id, key);

        let version_data = table_store.entry(db_key).or_default().clone();
        version_data.write().insert(checkpoint_id, *value);
        
        Ok(())
    }
    
    async fn db_set_single_id_merkle_nodes_batch(
        &self,
        table: &SMID,
        checkpoint_id: u64,
        tree_id: u64,
        nodes: &[SimpleMerkleNode<H>],
    ) -> anyhow::Result<()> {
        for node in nodes {
            self.db_insert_single_id_merkle_node(table, checkpoint_id, tree_id, node.key, &node.value).await?;
        }
        Ok(())
    }
}


// ---------------------------------------------------------------------------------
//
//                 CoreDatabaseDoubleIdMerkleStore Implementation
//
// ---------------------------------------------------------------------------------


#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseDoubleIdMerkleReader<H, Hs, DMID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_select_double_id_merkle_node_max_checkpoint(
        &self,
        table: &DMID,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<H> {
        let table_store = get_or_create_table(&self.double_id_merkle_store, table);
        let db_key = (tree_id, tree_sub_id, key);

        if let Some(version_data) = table_store.get(&db_key) {
            let versions = version_data.read();
            if let Some((_, hash)) = find_latest_version(&versions, checkpoint_id) {
                return Ok(hash);
            }
        }
        
        Ok(Hs::get_zero_hash(tree_height.saturating_sub(key.level) as usize))
    }
    
    async fn db_select_many_double_id_merkle_nodes_max_checkpoint(
        &self,
        table: &DMID,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<H>> {
        let mut results = Vec::with_capacity(keys.len());
        for &key in keys {
            results.push(self.db_select_double_id_merkle_node_max_checkpoint(table, max_checkpoint_id, tree_id, tree_sub_id, tree_height, key).await?);
        }
        Ok(results)
    }
}


#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseDoubleIdMerkleWriter<H, Hs, DMID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_insert_double_id_merkle_node(
        &self,
        table: &DMID,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        key: SimpleMerkleNodeKey,
        value: &H,
    ) -> anyhow::Result<()> {
        let table_store = get_or_create_table(&self.double_id_merkle_store, table);
        let db_key = (tree_id, tree_sub_id, key);

        let version_data = table_store.entry(db_key).or_default().clone();
        version_data.write().insert(checkpoint_id, *value);
        
        Ok(())
    }

    async fn db_set_double_id_merkle_nodes_batch(
        &self,
        table: &DMID,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        nodes: &[SimpleMerkleNode<H>],
    ) -> anyhow::Result<()> {
        for node in nodes {
            self.db_insert_double_id_merkle_node(table, checkpoint_id, tree_id, tree_sub_id, node.key, &node.value).await?;
        }
        Ok(())
    }
}


// ---------------------------------------------------------------------------------
//
//                  CoreDatabaseZeroIdMerkleStore Implementation
//
// ---------------------------------------------------------------------------------

#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseZeroIdMerkleReader<H, Hs, ZMID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_select_zero_id_merkle_node_max_checkpoint(
        &self,
        table: &ZMID,
        max_checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<H> {
        let table_store = get_or_create_table(&self.zero_id_merkle_store, table);
        
        if let Some(version_data) = table_store.get(key) {
            let versions = version_data.read();
            if let Some((_, hash)) = find_latest_version(&versions, max_checkpoint_id) {
                return Ok(hash);
            }
        }
        
        // Zero-ID merkle trees often don't have a defined height at this level,
        // so we assume the zero hash of level 0 (the leaf's sibling if it doesn't exist).
        // This detail may depend on the specific application's logic.
        Ok(Hs::get_zero_hash(0))
    }

    async fn db_select_many_zero_id_merkle_nodes_max_checkpoint(
        &self,
        table: &ZMID,
        max_checkpoint_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<H>> {
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            results.push(self.db_select_zero_id_merkle_node_max_checkpoint(table, max_checkpoint_id, key).await?);
        }
        Ok(results)
    }
}


#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseZeroIdMerkleWriter<H, Hs, ZMID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_insert_zero_id_merkle_node(
        &self,
        table: &ZMID,
        checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
        value: &H,
    ) -> anyhow::Result<()> {
        let table_store = get_or_create_table(&self.zero_id_merkle_store, table);
        let version_data = table_store.entry(*key).or_default().clone();
        version_data.write().insert(checkpoint_id, *value);
        Ok(())
    }

    async fn db_set_zero_id_merkle_nodes_batch(
        &self,
        table: &ZMID,
        checkpoint_id: u64,
        nodes: &[SimpleMerkleNode<H>],
    ) -> anyhow::Result<()> {
        for node in nodes {
            self.db_insert_zero_id_merkle_node(table, checkpoint_id, &node.key, &node.value).await?;
        }
        Ok(())
    }
}


// ---------------------------------------------------------------------------------
//
//                    CoreDatabaseTagTreeStore Implementation
//
// ---------------------------------------------------------------------------------

#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseTagTreeReader<H, Hs, TTID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn db_get_tag_tree_node_value(
        &self,
        table: &TTID,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<H>> {
        let table_store = get_or_create_table(&self.tag_tree_values, table);
        Ok(table_store.get(&(unique_pending_id, *key)).map(|v| *v))
    }

    async fn db_get_tag_tree_node_values(
        &self,
        table: &TTID,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<H>>> {
        let table_store = get_or_create_table(&self.tag_tree_values, table);
        Ok(keys.iter().map(|k| table_store.get(&(unique_pending_id, *k)).map(|v| *v)).collect())
    }

    async fn db_get_tag_tree_node_tag(
        &self,
        table: &TTID,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<H>> {
        let table_store = get_or_create_table(&self.tag_tree_tags, table);
        Ok(table_store.get(&(unique_pending_id, *key)).map(|v| *v))
    }

    async fn db_get_tag_tree_root(&self, table: &TTID, unique_pending_id: u64) -> anyhow::Result<Option<H>> {
        self.db_get_tag_tree_node_tag(table, unique_pending_id, &SimpleMerkleNodeKey::new_root()).await
    }

    async fn db_get_tag_tree_merkle_proof(
        &self,
        table: &TTID,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<TagTreeMerkleProof<H>> {
        todo!("Not implemented in InMemoryDb")
    }
}


#[async_trait]
impl<
    H: QHashBase + Send + Sync,
    Hs: MerkleZeroHasher<H> + Send + Sync,
    BMID: TIDBase + Debug,
    BMUID: TIDBase,
    UID: TIDBase,
    SID: TIDBase,
    DID: TIDBase,
    KID: TIDBase,
    SMID: TIDBase,
    DMID: TIDBase,
    ZMID: TIDBase,
    TTID: TIDBase,
> CoreDatabaseTagTreeWriter<H, Hs, TTID> for InMemoryDb<H, Hs, BMID, BMUID, UID, SID, DID, KID, SMID, DMID, ZMID, TTID>
{
    async fn set_tag_tree_tag_value(
        &self,
        table: &TTID,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
        tag: &H,
        value: &H,
    ) -> anyhow::Result<()> {
        let tags_table = get_or_create_table(&self.tag_tree_tags, table);
        let values_table = get_or_create_table(&self.tag_tree_values, table);
        let db_key = (unique_pending_id, *key);
        tags_table.insert(db_key, *tag);
        values_table.insert(db_key, *value);
        Ok(())
    }

    async fn set_tag_tree_tag_known_height(
        &self,
        table: &TTID,
        unique_pending_id: u64,
        _tag_tree_height: u8,
        key: &SimpleMerkleNodeKey,
        tag: &H,
    ) -> anyhow::Result<()> {let tags_table = get_or_create_table(&self.tag_tree_tags, table);
        let db_key = (unique_pending_id, *key);
        tags_table.insert(db_key, *tag);
        Ok(())
    }
    async fn set_tag_tree_tag(&self, table: &TTID, unique_pending_id: u64, key: &SimpleMerkleNodeKey, tag: &H) -> anyhow::Result<()> {
        let tags_table = get_or_create_table(&self.tag_tree_tags, table);
        let db_key = (unique_pending_id, *key);
        tags_table.insert(db_key, *tag);
        Ok(())
    }
}