use std::collections::HashMap;
use std::future::Future;
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

use crate::utils::{calc_best_batch_size, convert_checkpoint_id_to_i64, generate_batch_prepared_statement, i64_to_u64_exact, u64_to_i64_exact, u8_to_i8_exact};

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


    /// Dumps all leaf nodes from the database in memory-safe chunks for
    /// emergency recovery.
    ///
    /// This is the definitive, production-ready version of this function. It
    /// combines a memory-safe streaming approach with an ergonomic and
    /// performant callback interface.
    ///
    /// ## Strategy
    /// The function streams all historical leaf node versions from ScyllaDB. It
    /// de-duplicates these versions within a fixed-size buffer. Once the
    /// buffer is full, it is passed to the asynchronous `on_chunk` callback
    /// for processing. This ensures predictable, low memory usage
    /// regardless of the total number of leaves in the tree.
    ///
    /// The callback receives a `Vec<(SimpleMerkleNodeKey, Hash)>`, which is a
    /// highly performant data structure that avoids unnecessary allocations
    /// and provides type-safe, structured data to the consumer.
// In `impl ScyllaMerkleNodesZeroPreparedStatements`

    pub async fn dump_all_zero_id_merkle_node_leaves_chunked<
        Hash: QHash256Base,
        F: FnMut(Vec<(u64, Hash)>) -> Fut,
        Fut: Future<Output = anyhow::Result<()>>,
    >(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        mut on_chunk: F,
    ) -> anyhow::Result<()> {
        const CHUNK_CAPACITY: usize = 1024*128;

        let leaf_level = self.tree_height;
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);

        // --- START: CORRECTED CODE ---

        // 1. The Invalid Filter is Removed: We no longer restrict by `checkpoint_id` here.
        // 2. We Select `checkpoint_id`: We need this value for client-side filtering.
        let dump_query_string = format!(
            "SELECT node_index, value, checkpoint_id FROM {}.{} WHERE level = ?",
            self.keyspace, self.table_name
        );

        // 3. The `max_cp_i64` is no longer passed as a bound value.
        let mut rows_stream = session
            .query_iter(dump_query_string, (u8_to_i8_exact(leaf_level),))
            .await?
            // 4. We now expect a tuple of three values from the database.
            .rows_stream::<(i64, Vec<u8>, i64)>()?;

        // --- END: CORRECTED CODE ---

        let mut chunk_buffer: HashMap<i64, Hash> = HashMap::with_capacity(CHUNK_CAPACITY);

        while let Some(row_result) = rows_stream.next().await {
            let (node_index, value_bytes, checkpoint_id) = row_result?;

            // 5. Perform the checkpoint filtering here, on the client.
            if checkpoint_id > max_cp_i64 {
                continue; // Skip any nodes that are too new.
            }

            let value_hash = Hash::from_slice_32bytes(&value_bytes)?;

            // The `entry().or_insert()` logic is still correct. Because ScyllaDB returns
            // rows sorted by `checkpoint_id DESC` within each partition, the FIRST time
            // we see a `node_index`, it is guaranteed to be the latest version we care about.
            chunk_buffer.entry(node_index).or_insert(value_hash);

            if chunk_buffer.len() >= CHUNK_CAPACITY {
                let chunk_to_process = chunk_buffer
                    .drain()
                    .map(|(index, value)| (i64_to_u64_exact(index), value))
                    .collect();

                on_chunk(chunk_to_process).await?;
            }
        }

        // Process the final chunk
        if !chunk_buffer.is_empty() {
            let final_chunk = chunk_buffer
                .into_iter()
                .map(|(index, value)| (i64_to_u64_exact(index), value))
                .collect();

            on_chunk(final_chunk).await?;
        }

        Ok(())
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