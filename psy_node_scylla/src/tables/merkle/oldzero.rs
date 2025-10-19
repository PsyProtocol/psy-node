use std::sync::Arc;

use anyhow::Context;
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
            insert_batch_serialized_256_prepared: Arc::new(generate_batch_prepared_statement(&session, &insert_prepared, 512).await?),
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
    pub async fn dump_non_zero_latest_nodes_for_tree_max_checkpoint_internal<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<SimpleMerkleNode<Hash>>> {
        const CONCURRENT_LEVEL_PROCESSING_LIMIT: usize = 8; // How many levels to process at once.
        const CONCURRENT_FETCH_LIMIT_PER_LEVEL: usize = 512; // How many nodes to fetch concurrently within a single level.

    let select_distinct_indices_statement = Statement::new(&format!(
        "SELECT DISTINCT node_index FROM {}.{} WHERE level = ?",
        self.keyspace, self.table_name
    ));
    let select_distinct_indices_prepared = session.prepare(select_distinct_indices_statement).await?;
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);

        let results_per_level = stream::iter(0..self.tree_height)
            .map(|level| {
                let session = session.clone();
                let discover_prep = select_distinct_indices_prepared.clone();
                let fetch_prep = self.select_1_prepared.clone();
                let level_i8 = u8_to_i8_exact(level);

                async move {
                    // Phase 1: Discover all unique node indices for this level.
                    let indices: Vec<i64> = session
                        .execute_iter(discover_prep, (level_i8,))
                        .await?
                        .rows_stream::<(i64,)>()?
                        .map_ok(|(idx,)| idx)
                        .try_collect()
                        .await?;

                    if indices.is_empty() {
                        return anyhow::Ok(Vec::new());
                    }

                    // Phase 2: Fetch the latest value for each discovered index concurrently.
                    let nodes_for_level = stream::iter(indices)
                        .map(|node_index_i64| {
                            let fetch_prep = fetch_prep.clone();
                            async move {
                                let res = session
                                    .execute_unpaged(&fetch_prep, (level_i8, node_index_i64, max_cp_i64))
                                    .await?;

                                // The query returns at most one row.
                                if let Some(row) = res.into_rows_result()?.maybe_first_row::<(Vec<u8>,)>()? {
                                    let value = Hash::from_bytes(&row.0)?;
                                    let key = SimpleMerkleNodeKey {
                                        level,
                                        index: node_index_i64 as u64,
                                    };
                                    anyhow::Ok::<_>(Some(SimpleMerkleNode { key, value }))
                                } else {
                                    // This case is unlikely if the index was discovered, but possible in race conditions
                                    // or if all versions are after max_checkpoint_id. We return None and filter it out.
                                    Ok(None)
                                }
                            }
                        })
                        .buffer_unordered(CONCURRENT_FETCH_LIMIT_PER_LEVEL)
                        .try_collect::<Vec<Option<SimpleMerkleNode<Hash>>>>()
                        .await?;

                    // Filter out the None values and return the collected nodes for this level.
                    Ok(nodes_for_level.into_iter().flatten().collect::<Vec<_>>())
                }
            })
            .buffer_unordered(CONCURRENT_LEVEL_PROCESSING_LIMIT)
            .try_collect::<Vec<Vec<SimpleMerkleNode<Hash>>>>()
            .await?;

        // Flatten the results from all levels into a single vector.
        let all_nodes: Vec<SimpleMerkleNode<Hash>> = results_per_level.into_iter().flatten().collect();

        Ok(all_nodes)
    }
    /// Retrieves latest values for multiple keys <= max_checkpoint_id.
    /// Optimized: concurrent chunks (limit 512 for better throughput, assuming safe).
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
}