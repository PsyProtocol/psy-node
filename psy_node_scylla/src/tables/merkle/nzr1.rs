use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use dashmap::DashMap;
use parth_core::protocol::core_types::QDBHashBase;
use psy_node_core::store::traits::core_db::MerkleTreeDumpStrategy;
use rayon::slice::{ParallelSlice};
use rayon::iter::ParallelIterator;
use futures::{future::join_all, stream, StreamExt, TryStreamExt};

use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::{
        db::table::QDatabaseTableRoutingKey,
        hash::{fast_node_serializer::{QMerkleStoreFastZeroNodeSerializer, QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE}, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}},
    },
    protocol::core_types::{QHash256Base, QHashBase},
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{batch::Batch, prepared::PreparedStatement, Statement},
};

use crate::utils::{calc_best_batch_size, convert_checkpoint_id_to_i64, generate_batch_prepared_statement, u64_to_i64_exact, u8_to_i8_exact};

#[derive(Clone)]
pub struct ScyllaMerkleNodesZeroPreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,
    pub select_1_statement: Statement,
    pub select_1_prepared: Arc<PreparedStatement>,

    //pub insert_batch_serialized_512_prepared: Arc<Batch>,
    pub insert_batch_serialized_256_prepared: Arc<Batch>,
    pub insert_batch_serialized_128_prepared: Arc<Batch>,
    pub insert_batch_serialized_64_prepared: Arc<Batch>,
    //pub insert_batch_serialized_32_prepared: Arc<Batch>,

    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
    pub tree_height: u8,
}

impl ScyllaMerkleNodesZeroPreparedStatements {
    /// Creates prepared statements from an existing session.
    /// Prepares statements for inserts, single selects, and the dump query.
    pub async fn new_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
        tree_height: u8,
    ) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(&format!(
            "INSERT INTO {}.{} (level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?)",
            keyspace, table_name
        ));
        let insert_prepared = session.prepare(insert_1_statement.clone()).await?;
        let select_1_statement = Statement::new(&format!(
            "SELECT value FROM {}.{} WHERE level = ? AND node_index = ? AND checkpoint_id <= ? LIMIT 1",
            keyspace, table_name
        ));
        let select_1_prepared = session.prepare(select_1_statement.clone()).await?;
        // Prepare the dump-specific select: fetches node_index and value, ordered by clustering (node_index ASC, checkpoint_id DESC).

        Ok(Self {
            insert_batch_serialized_256_prepared: Arc::new(generate_batch_prepared_statement(&session, &insert_prepared, 256).await?),
            insert_batch_serialized_128_prepared: Arc::new(generate_batch_prepared_statement(&session, &insert_prepared, 128).await?),
            insert_batch_serialized_64_prepared: Arc::new(generate_batch_prepared_statement(&session, &insert_prepared, 64).await?), 
            insert_1_prepared: Arc::new(insert_prepared),
            select_1_prepared: Arc::new(select_1_prepared),
            insert_1_statement: insert_1_statement,
            select_1_statement: select_1_statement,       
            keyspace: keyspace.to_string(),
            table_name: table_name.to_string(),
            table_key,
            tree_height,
        })
    }

    /// Creates the table if it doesn't exist.
    /// No changes needed; schema is optimal for operations.
    pub async fn create_table(session: Arc<Session>, keyspace: &str, table_name: &str, _table_key: QDatabaseTableRoutingKey) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {}.{} (
                    level TINYINT,
                    node_index BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((level), node_index, checkpoint_id)
                ) WITH CLUSTERING ORDER BY (node_index ASC, checkpoint_id DESC)",
                    keyspace, table_name
                ),
                &[],
            )
            .await?;
        session.await_schema_agreement().await?;
        Ok(())
    }

    /// Creates the table and prepares statements.
    pub async fn new_create_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
        tree_height: u8,
    ) -> anyhow::Result<Self> {
        Self::create_table(session.clone(), keyspace, table_name, table_key).await?;
        Self::new_from_session(session, keyspace, table_name, table_key, tree_height).await
    }
}

impl ScyllaMerkleNodesZeroPreparedStatements {
    /// Retrieves the latest value for a single node key <= checkpoint_id.
    /// Returns zero hash if not found.
    /// Optimized: uses prepared statement and LIMIT 1.
    pub async fn select_zero_id_merkle_node_max_checkpoint_internal<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        let res = session
            .execute_unpaged(
                &self.select_1_prepared,
                (
                    u8_to_i8_exact(key.level),
                    u64_to_i64_exact(key.index),
                    convert_checkpoint_id_to_i64(checkpoint_id),
                ),
            )
            .await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => Ok(Hash::from_bytes(&row.0)?),
            None => Ok(Hasher::get_zero_hash((self.tree_height - key.level) as usize)), // Return zero hash if not found
        }
    }
// In `impl ScyllaMerkleNodesZeroPreparedStatements`

    /// Dumps all latest non-zero nodes for the entire tree at or before a given checkpoint_id.
    ///
    /// This implementation is highly optimized to prevent pulling historical data to the client.
    /// It works in two phases for each tree level, executed concurrently:
    /// 1. **Discover**: A `SELECT DISTINCT node_index` query is run for the level to find all unique
    ///    nodes that have ever existed. This is a metadata-only query and is very fast.
    /// 2. **Fetch**: For each discovered `node_index`, it executes the highly efficient `select_1` query
    ///    (`... WHERE ... LIMIT 1`) to get the single, latest version of that node at or before
    ///    the target checkpoint.
    ///
    /// This strategy minimizes data transfer and leverages Scylla's strengths for point lookups,
    /// ensuring the dump is as fast and efficient as possible.
   
   
   pub async fn select_many_zero_id_merkle_nodes_max_checkpoint_internal<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        const CONCURRENT_LIMIT: usize = 512; // Increased for better performance; monitor for timeouts.
        let mut results = Vec::with_capacity(keys.len());
        for chunk in keys.chunks(CONCURRENT_LIMIT) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let prep = self.select_1_prepared.clone();
                    let level_i8 = u8_to_i8_exact(key.level);
                    let index_i64 = u64_to_i64_exact(key.index);
                    let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
                    async move {
                        let res: QueryResult = session.execute_unpaged(&prep, (level_i8, index_i64, max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                            Hash::from_bytes(&row.0)
                        } else {
                            Ok(Hasher::get_zero_hash((self.tree_height - key.level) as usize))
                        }
                    }
                })
                .collect();
            let chunk_results = join_all(futures).await;
            for res in chunk_results {
                results.push(res?);
            }
        }
        Ok(results)
    }

pub async fn dump_all_zero_id_merkle_node_leaves_sparse_sub_trees<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<HashMap<u64, Hash>> {
        let output_map = DashMap::new();

        // Start the recursive scan from the root of the tree (level 0, index 0).
        self.sparse_dump_recursive(session, max_checkpoint_id, 0, 0, &output_map).await?;

        Ok(output_map.into_iter().collect())
    }
    
    /// NEW HELPER: Retrieves a node value if it exists, otherwise returns None.
    /// This is the clean, internal way to check for node existence.
    pub async fn select_optional_zero_id_merkle_node_internal<Hash: QDBHashBase>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>> {
        let res = session
            .execute_unpaged(
                &self.select_1_prepared,
                (
                    u8_to_i8_exact(key.level),
                    u64_to_i64_exact(key.index),
                    convert_checkpoint_id_to_i64(checkpoint_id),
                ),
            )
            .await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => Ok(Some(Hash::from_slice_32bytes(&row.0)?)),
            None => Ok(None),
        }
    
    }
    async fn sparse_dump_recursive<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        level: u8,
        node_index: u64,
        output_map: &DashMap<u64, Hash>,
    ) -> anyhow::Result<()> {
        //println!("sparse_dump_recursive: level {}, index {}", level, node_index);
        // We don't need to check the absolute root at (0,0), but every node below it.
        // If the root of the subtree we're asked to scan doesn't exist, prune the entire branch.
        if level > 0 {
            if self.select_optional_zero_id_merkle_node_internal::<Hash>(session, max_checkpoint_id, SimpleMerkleNodeKey { level, index: node_index }).await?.is_none() {
                return Ok(());
            }
        }
        const SUBTREE_SCAN_LEVEL_DIFF: u8 = 8;
        let scan_level = (level + SUBTREE_SCAN_LEVEL_DIFF).min(self.tree_height);
        // BASE CASE: If the next scan level is the leaf level, we scan for leaves and finish.
        if scan_level == self.tree_height {
            let level_diff = scan_level - level;
            let start_child_index = node_index << level_diff;
            let end_child_index = start_child_index + (1u64 << level_diff) - 1;
            let leaves = self.scan_tree_level_caps::<Hash>(session, max_checkpoint_id, self.tree_height, start_child_index, end_child_index).await?;
            for (i, hash_opt) in leaves.into_iter().enumerate() {
                if let Some(hash) = hash_opt {
                    output_map.insert(start_child_index + i as u64, hash);
                }
            }
            return Ok(());
        }
        // RECURSIVE STEP: Scan for intermediate "caps" and recurse on the ones that exist.
        let level_diff = scan_level - level;
        let start_child_index = node_index << level_diff;
        let end_child_index = start_child_index + (1u64 << level_diff) - 1;
        let caps = self.scan_tree_level_caps::<Hash>(session, max_checkpoint_id, scan_level, start_child_index, end_child_index).await?;
       
        let child_indices_to_explore: Vec<u64> = caps
            .into_iter()
            .enumerate()
            .filter_map(|(i, hash_opt)| hash_opt.map(|_| start_child_index + i as u64))
            .collect();
        let mut futures = Vec::new();
        for child_node_index in child_indices_to_explore {
            let fut = self.sparse_dump_recursive(
                session,
                max_checkpoint_id,
                scan_level,
                child_node_index,
                output_map,
            );
            futures.push(Box::pin(fut));
        }
        let results = join_all(futures).await;
        for result in results {
            result?;
        }
        Ok(())
    }
    /// Inserts a single node at checkpoint_id.
    /// Optimized: uses prepared statement.
    pub async fn insert_zero_id_merkle_node_internal(
        &self,
        session: &Session,
        checkpoint_id: u64,
        key: SimpleMerkleNodeKey,
        value: &[u8],
    ) -> anyhow::Result<()> {
        session
            .execute_unpaged(
                &self.insert_1_prepared,
                (
                    u8_to_i8_exact(key.level),
                    u64_to_i64_exact(key.index),
                    convert_checkpoint_id_to_i64(checkpoint_id),
                    value,
                ),
            )
            .await?;
        Ok(())
    }

    /// Batch inserts multiple nodes at checkpoint_id.
    /// Optimized: increased batch size to 512 for higher throughput; streams batches concurrently via join_all.
    pub async fn set_zero_id_merkle_nodes_batch_internal<Hash: QHashBase>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()> {
        const BATCH_SIZE: usize = 512; // Increased for performance; safe assuming typical node sizes.
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i8, i64, i64, Vec<u8>)>> = Vec::new();
        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        for chunk in nodes.chunks(BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _ in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((
                        u8_to_i8_exact(n.key.level),
                        u64_to_i64_exact(n.key.index),
                        checkpoint_i64,
                        n.value.to_bytes()?,
                    ))
                })
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list
            .iter()
            .zip(value_list.into_iter())
            .map(|(batch, values)| session.batch(batch, values))
            .collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }
}



impl ScyllaMerkleNodesZeroPreparedStatements {

    async fn set_zero_id_merkle_nodes_batch_fast_serialize_with_batch_size_internal<Hash: QHash256Base>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        data: &[u8],
        batch_size: usize,
    ) -> anyhow::Result<()> {
        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        if data.len() % QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE != 0 {
            anyhow::bail!("Data length is not a multiple of zero id node size");
        }
        let num_nodes = data.len() / QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE;

        if num_nodes == 0 {
            return Ok(());
        }

        const CONCURRENCY_LIMIT: usize = 64; // Tuned for typical Scylla clusters


        // Parallel deserialization using rayon
        let values: Vec<(i8, i64, i64, [u8; 32])> = data
            .par_chunks(QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE)
            .map(|slice| {
                QMerkleStoreFastZeroNodeSerializer::deserialize_zero_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64)
            })
            .collect();

        // Map batch size to pre-prepared batch
        let batch_prepared = match batch_size {
            //512 => &self.insert_batch_serialized_512_prepared,
            256 => &self.insert_batch_serialized_256_prepared,
            128 => &self.insert_batch_serialized_128_prepared,
            64 => &self.insert_batch_serialized_64_prepared,
            //32 => &self.insert_batch_serialized_32_prepared,
            _ => unreachable!(),
        };

        // Process batches concurrently
        let chunks = values.chunks(batch_size);
        stream::iter(chunks)
            .map(anyhow::Ok)
            .try_for_each_concurrent(CONCURRENCY_LIMIT, |chunk| {
                let batch_prepared = batch_prepared.clone();
                async move {
                    if chunk.len() == batch_size {
                        session.batch(&batch_prepared, chunk).await.context("Batch insert failed")?;
                    } else {
                        let mut batch = Batch::default();
                        for _ in 0..chunk.len() {
                            batch.append_statement(self.insert_1_statement.clone());
                        }
                        session.batch(&batch, chunk).await.context("Partial batch insert failed")?;
                    }
                    Ok(())
                }
            })
            .await?;

        Ok(())
    }
     
    pub async fn set_zero_id_merkle_nodes_batch_fast_serialize<Hash: QHash256Base>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()> {
        if data.len() % QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE != 0 {
            anyhow::bail!("Data length is not a multiple of zero id node size");
        }
        let num_nodes = data.len() / QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE;
        if num_nodes == 0 {
            return Ok(());
        }
        
        let batch_size = calc_best_batch_size(num_nodes, &[256, 128, 64]);
        self.set_zero_id_merkle_nodes_batch_fast_serialize_with_batch_size_internal::<Hash>(session, checkpoint_id, data, batch_size).await

    }


    pub async fn dump_all_zero_id_merkle_node_leaves_fast<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<HashMap<u64, Hash>> {
        let total_leaves = 1u64 << self.tree_height;
        let mut data_map: HashMap<u64, Hash> = HashMap::with_capacity(total_leaves as usize);
        // The end_index for dump_leaves_to_hash_map is exclusive.
        self.dump_leaves_to_hash_map::<Hash>(session, max_checkpoint_id, 0, total_leaves, &mut data_map).await?;
        Ok(data_map)
    }
    

    pub async fn dump_all_zero_id_merkle_node_leaves_append_only<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<HashMap<u64, Hash>> {
        let total_leaves = 1u64 << self.tree_height;
        if total_leaves == 0 {
            return Ok(HashMap::new());
        }

        let leaf_level = self.tree_height;
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
        let level_i8 = u8_to_i8_exact(leaf_level);

        // Binary search to find the first zero leaf. This is more robust for the append-only assumption.
        // It efficiently finds the total number of non-zero leaves.
        let mut low = 0u64;
        let mut high = total_leaves.saturating_sub(1);
        let mut first_zero_idx = total_leaves; // Assume all leaves are non-zero initially.

        while low <= high {
            let mid = low + (high - low) / 2;
            
            let res = session.execute_unpaged(&self.select_1_prepared, (level_i8, u64_to_i64_exact(mid), max_cp_i64)).await?;
            let is_present = res.into_rows_result()?.maybe_first_row::<(Vec<u8>,)>()?.is_some();

            if is_present {
                // The leaf at `mid` is non-zero, so the first zero leaf must be to the right.
                low = mid.saturating_add(1);
            } else {
                // The leaf at `mid` is zero. This could be the first one. Store it and search to the left.
                first_zero_idx = mid;
                if mid == 0 {
                    break;
                }
                high = mid.saturating_sub(1);
            }
        }

        let mut data_map = HashMap::new();
        if first_zero_idx > 0 {
            // We now know that leaves from 0 to first_zero_idx - 1 are non-zero.
            // Dump this contiguous range in one efficient bulk operation.
            self.dump_leaves_to_hash_map::<Hash>(session, max_checkpoint_id, 0, first_zero_idx, &mut data_map).await?;
        }
        
        Ok(data_map)
    }

    /// Helper function to perform a bulk read of leaves in a given range and populate a HashMap.
    async fn dump_leaves_to_hash_map<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        start_index: u64,
        end_index: u64, // Exclusive
        data_map: &mut HashMap<u64, Hash>,
    ) -> anyhow::Result<()> {
        if start_index >= end_index {
            return Ok(());
        }
        // scan_tree_level_caps takes an inclusive end_index.
        let results = self.scan_tree_level_caps::<Hash>(session, max_checkpoint_id, self.tree_height, start_index, end_index - 1).await?;
        for (i, maybe_hash) in results.into_iter().enumerate() {
            if let Some(hash) = maybe_hash {
                data_map.insert(start_index + i as u64, hash);
            }
        }
        Ok(())
    }
    /// Scans a range of nodes at a specific tree level, returning a vector of optional hashes.
    async fn scan_tree_level_caps<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        level: u8, 
        start_index: u64,
        end_index: u64, // Inclusive
    ) -> anyhow::Result<Vec<Option<Hash>>> {
        const CONCURRENT_LIMIT: usize = 512;
        if start_index > end_index {
            return Ok(Vec::new());
        }

        let level_i8 = u8_to_i8_exact(level);
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);

        stream::iter(start_index..=end_index)
            .map(|index| {
                let session = session.clone();
                let prep = self.select_1_prepared.clone();
                async move {
                    let index_i64 = u64_to_i64_exact(index);
                    let res = session.execute_unpaged(&prep, (level_i8, index_i64, max_cp_i64)).await?;
                    let rows = res.into_rows_result()?;
                    if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                        Ok(Some(Hash::from_bytes(&row.0).context("Failed to parse hash from bytes")?))
                    } else {
                        Ok(None)
                    }
                }
            })
            .buffered(CONCURRENT_LIMIT)
            .try_collect()
            .await
    }
    async fn find_left_most_zero_merkle_path<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        sub_root: SimpleMerkleNodeKey,
        scan_cap_batch_log_2: u8,
        data_map: &DashMap<u64, Hash>,
    ) -> anyhow::Result<()> {
        todo!("")
    }
    async fn dump_tree_span_v2<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        level: u8, 
        start_index: u64,
        end_index: u64,
        data_map: &DashMap<u64, Hash>,
    ) -> anyhow::Result<()> {

        let count = end_index - start_index;
        const CONCURRENT_LIMIT: usize = 512; // Increased for better performance; monitor for timeouts.
        let level_i8 = u8_to_i8_exact(level);
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);

        let batch_count = count as usize / CONCURRENT_LIMIT + if (count as usize % CONCURRENT_LIMIT) > 0 {1} else {0};
        for i in 0..batch_count {
            let max_value = if i == batch_count-1 {
                let mod_res = count as usize % CONCURRENT_LIMIT;
                if mod_res == 0 {
                    CONCURRENT_LIMIT
                } else {
                    mod_res
                }
            } else {
                CONCURRENT_LIMIT
            };

            let futures: Vec<_> = (0..max_value)
                .map(|idx| {
                    let prep = self.select_1_prepared.clone();
                    let idx_u64 =(i*CONCURRENT_LIMIT + idx) as u64 + start_index;
                    let index_i64 = u64_to_i64_exact(idx_u64);
                    async move {
                        let res: QueryResult = session.execute_unpaged(&prep, (level_i8, index_i64, max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                            if row.0.len() != 32 {
                                anyhow::bail!("Invalid hash length retrieved from database");
                            }
                            data_map.insert(idx_u64, Hash::from_owned_32bytes(row.0.try_into().unwrap()));
                        }
                        Ok(())
                    }
                }).collect();
            let batch_results = join_all(futures).await;
            for res in batch_results {
                res?;
            }
        }

        Ok(())

    }
    async fn dump_leaves_to_dash_map<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        start_index: u64,
        end_index: u64,
        data_map: &DashMap<u64, Hash>,
    ) -> anyhow::Result<()> {

        let count = end_index - start_index;
        const CONCURRENT_LIMIT: usize = 512; // Increased for better performance; monitor for timeouts.
        let level_i8 = u8_to_i8_exact(self.tree_height);
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);

        let batch_count = count as usize / CONCURRENT_LIMIT + if (count as usize % CONCURRENT_LIMIT) > 0 {1} else {0};
        for i in 0..batch_count {
            let max_value = if i == batch_count-1 {
                let mod_res = count as usize % CONCURRENT_LIMIT;
                if mod_res == 0 {
                    CONCURRENT_LIMIT
                } else {
                    mod_res
                }
            } else {
                CONCURRENT_LIMIT
            };

            let futures: Vec<_> = (0..max_value)
                .map(|idx| {
                    let prep = self.select_1_prepared.clone();
                    let idx_u64 =(i*CONCURRENT_LIMIT + idx) as u64 + start_index;
                    let index_i64 = u64_to_i64_exact(idx_u64);
                    async move {
                        let res: QueryResult = session.execute_unpaged(&prep, (level_i8, index_i64, max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                            if row.0.len() != 32 {
                                anyhow::bail!("Invalid hash length retrieved from database");
                            }
                            data_map.insert(idx_u64, Hash::from_owned_32bytes(row.0.try_into().unwrap()));
                        }
                        Ok(())
                    }
                }).collect();
            let batch_results = join_all(futures).await;
            for res in batch_results {
                res?;
            }
        }

        Ok(())

    }
    async fn dump_tree_span<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        level: u8, 
        start_index: u64,
        end_index: u64,
        data_map: &DashMap<u64, Hash>,
    ) -> anyhow::Result<()> {
        if start_index >= end_index {
            anyhow::bail!("Invalid index range, start_index >= end_index - start_index: {}, end_index: {}", start_index, end_index);
        }

        let count = end_index - start_index;
        const CONCURRENT_LIMIT: usize = 512; // Increased for better performance; monitor for timeouts.
        let level_i8 = u8_to_i8_exact(level);
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);

        let batch_count = count as usize / CONCURRENT_LIMIT + if (count as usize % CONCURRENT_LIMIT) > 0 {1} else {0};
        for i in 0..batch_count {
            let max_value = if i == batch_count-1 {
                let mod_res = count as usize % CONCURRENT_LIMIT;
                if mod_res == 0 {
                    CONCURRENT_LIMIT
                } else {
                    mod_res
                }
            } else {
                CONCURRENT_LIMIT
            };

            let futures: Vec<_> = (0..max_value)
                .map(|idx| {
                    let prep = self.select_1_prepared.clone();
                    let idx_u64 =(i*CONCURRENT_LIMIT + idx) as u64 + start_index;
                    let index_i64 = u64_to_i64_exact(idx_u64);
                    async move {
                        let res: QueryResult = session.execute_unpaged(&prep, (level_i8, index_i64, max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                            if row.0.len() != 32 {
                                anyhow::bail!("Invalid hash length retrieved from database");
                            }
                            data_map.insert(idx_u64, Hash::from_owned_32bytes(row.0.try_into().unwrap()));
                        }
                        Ok(())
                    }
                }).collect();
            let batch_results = join_all(futures).await;
            for res in batch_results {
                res?;
            }
        }
        Ok(())

    }/* 

    async fn binary_search_non_zero<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        from_level: u8,
        mut index: u64,
    ) -> anyhow::Result<Vec<Vec<SimpleMerkleNode<Hash>>>>{
        // if the tree is append only or has some empty portion to the right, we can do a binary search to find the first non-zero node
        // first find the first non-zero
        // gets a merkle path from 


        let level_count = (self.tree_height - from_level) as usize;
        let keys = Vec::with_capacity(level_count);
        for i in self.tree_height..=from_level {
            keys.push(SimpleMerkleNodeKey {
                level: i,
                index,
            });
            index /= 2;
        }

        Ok(())


    }


    async fn dump_tree_span_batch<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        level: u8, 
        start_index: u64,
        end_index: u64,
        batch_size: usize,
    ) -> anyhow::Result<Vec<Vec<SimpleMerkleNode<Hash>>>>{

    }

    async fn dump_all_zero_id_merkle_node_leaves_vec_find_empty_limb_strategy<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<SimpleMerkleNode<Hash>>>{
        const START_LEVEL: usize = 10;
        anyhow::bail!("Not implemented");
    
        
    }
*/

    pub async fn dump_all_zero_id_merkle_node_leaves_vec<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        strategy: MerkleTreeDumpStrategy,
    ) -> anyhow::Result<Vec<SimpleMerkleNode<Hash>>>{



        anyhow::bail!("Not implemented");
        
    }
}