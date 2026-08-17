use std::{collections::HashMap, sync::Arc};

use anyhow::Context;
use futures::{future::join_all, stream, StreamExt, TryStreamExt};
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::{
        db::table::QDatabaseTableRoutingKey,
        hash::{
            checkpointed_merkle_node::CheckpointedMerkleHash, fast_node_serializer::{QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE, QMerkleStoreFastZeroNodeSerializer}, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}
        },
    },
    protocol::core_types::{QDBHashBase, QHash256Base, QHashBase},
};
use psy_node_core::store::traits::core_db::MerkleTreeDumpStrategy;
use psy_node_core::store::typed::CheckpointId;

use crate::rollback::{
    CommitMutationSink, ScyllaPhysicalTableId, physical_table_by_name, record_zero_merkle_put,
};
use rayon::{iter::ParallelIterator, slice::ParallelSlice};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{batch::Batch, prepared::PreparedStatement, Statement},
};

use crate::{table_creator::create_table_if_not_exists, utils::{
    calc_best_batch_size, convert_checkpoint_id_to_i64, generate_batch_prepared_statement, i64_to_u64_exact, u8_to_i8_exact, u64_to_i64_exact
}};

/// Decode a fast-serialized zero-id node set and hand every row to `sink`.
///
/// A free function rather than a method: it needs only the physical table
/// identity, and keeping it session-free means the property that matters -- one
/// locator recorded per row that will be written -- is testable directly.
pub fn plan_zero_merkle_nodes<Hash: QHash256Base>(
    physical_table: ScyllaPhysicalTableId,
    checkpoint_id: u64,
    data: &[u8],
    sink: &dyn CommitMutationSink,
) -> anyhow::Result<ZeroMerkleWritePlan> {
    let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
    if data.len() % QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE != 0 {
        anyhow::bail!("Data length is not a multiple of zero id node size");
    }
    let values: Vec<(i8, i64, i64, [u8; 32])> = data
        .par_chunks(QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE)
        .map(|slice| {
            QMerkleStoreFastZeroNodeSerializer::deserialize_zero_id_node_signed_insert_tuple::<Hash>(
                slice,
                checkpoint_i64,
            )
        })
        .collect();
    let checkpoint = CheckpointId::try_new(checkpoint_id)?;
    for (level, node_index, _, _) in &values {
        record_zero_merkle_put(
            sink,
            physical_table,
            u8::try_from(*level)?,
            u64::try_from(*node_index)?,
            checkpoint,
        )?;
    }
    Ok(ZeroMerkleWritePlan { values })
}

/// A decoded zero-id Merkle node set, recorded and ready to write.
///
/// Carrying the decoded rows forward means the fast-serialized blob is parsed
/// once even though planning and execution are separate steps.
pub struct ZeroMerkleWritePlan {
    values: Vec<(i8, i64, i64, [u8; 32])>,
}

impl ZeroMerkleWritePlan {
    /// How many physical rows this plan will write.  Equal to the number of
    /// locators handed to the sink, which a caller can assert.
    pub fn row_count(&self) -> usize {
        self.values.len()
    }
}

#[derive(Clone)]
pub struct ScyllaMerkleNodesZeroPreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,
    pub select_1_statement: Statement,
    pub select_1_prepared: Arc<PreparedStatement>,
    pub select_1_and_checkpoint_statement: Statement,
    pub select_1_and_checkpoint_prepared: Arc<PreparedStatement>,

    //pub insert_batch_serialized_512_prepared: Arc<Batch>,
    pub insert_batch_serialized_256_prepared: Arc<Batch>,
    pub insert_batch_serialized_128_prepared: Arc<Batch>,
    pub insert_batch_serialized_64_prepared: Arc<Batch>,
    //pub insert_batch_serialized_32_prepared: Arc<Batch>,
    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
    pub tree_height: u8,
    /// Which of the four zero-id Merkle tables this adapter serves.
    ///
    /// Resolved once at construction and required, not optional: registering a
    /// new zero-id table without adding it to the typed registry would
    /// otherwise leave its writes unrecorded, and rollback would not know they
    /// happened.  Failing at startup is the only place that is visible.
    pub physical_table: ScyllaPhysicalTableId,
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
        let select_1_and_checkpoint_statement = Statement::new(&format!(
            "SELECT value, checkpoint_id FROM {}.{} WHERE level = ? AND node_index = ? AND checkpoint_id <= ? LIMIT 1",
            keyspace, table_name
        ));
        let select_1_and_checkpoint_prepared = session.prepare(select_1_and_checkpoint_statement.clone()).await?;
        // Prepare the dump-specific select: fetches node_index and value, ordered by
        // clustering (node_index ASC, checkpoint_id DESC).

        Ok(Self {
            insert_batch_serialized_256_prepared: Arc::new(generate_batch_prepared_statement(&session, &insert_prepared, 256).await?),
            insert_batch_serialized_128_prepared: Arc::new(generate_batch_prepared_statement(&session, &insert_prepared, 128).await?),
            insert_batch_serialized_64_prepared: Arc::new(generate_batch_prepared_statement(&session, &insert_prepared, 64).await?),
            insert_1_prepared: Arc::new(insert_prepared),
            select_1_prepared: Arc::new(select_1_prepared),
            select_1_and_checkpoint_prepared: Arc::new(select_1_and_checkpoint_prepared),
            insert_1_statement: insert_1_statement,
            select_1_statement: select_1_statement,
            select_1_and_checkpoint_statement: select_1_and_checkpoint_statement,
            keyspace: keyspace.to_string(),
            table_name: table_name.to_string(),
            table_key,
            tree_height,
            physical_table: physical_table_by_name(table_name).ok_or_else(|| {
                anyhow::anyhow!(
                    "zero-id Merkle table {table_name:?} is not in the typed registry, so its \
                     writes could not be recorded for rollback"
                )
            })?,
        })
    }

    /// Creates the table if it doesn't exist.
    /// No changes needed; schema is optimal for operations.
    pub async fn create_table(session: Arc<Session>, keyspace: &str, table_name: &str, _table_key: QDatabaseTableRoutingKey) -> anyhow::Result<()> {
        create_table_if_not_exists(
                &session,
                keyspace,
                table_name,
                &format!(
                    "CREATE TABLE IF NOT EXISTS {}.{} (
                    level TINYINT,
                    node_index BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((level), node_index, checkpoint_id)
                ) WITH CLUSTERING ORDER BY (node_index ASC, checkpoint_id DESC)",
                    keyspace, table_name
                ),
            )
            .await?;
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
    pub async fn select_zero_id_merkle_node_and_checkpoint_max_checkpoint_internal<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<CheckpointedMerkleHash<Hash>> {
        let res = session
            .execute_unpaged(
                &self.select_1_and_checkpoint_prepared,
                (
                    u8_to_i8_exact(key.level),
                    u64_to_i64_exact(key.index),
                    convert_checkpoint_id_to_i64(checkpoint_id),
                ),
            )
            .await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>, i64)>()? {
            Some(row) => Ok(CheckpointedMerkleHash{
                checkpoint_id: i64_to_u64_exact(row.1),
                value: Hash::from_bytes(&row.0)?, 
            }),
            None => Ok(CheckpointedMerkleHash{
                checkpoint_id,
                value: Hasher::get_zero_hash((self.tree_height - key.level) as usize), 
            }),
        }
    }
    // In `impl ScyllaMerkleNodesZeroPreparedStatements`

    /// Dumps all latest non-zero nodes for the entire tree at or before a given
    /// checkpoint_id.
    ///
    /// This implementation is highly optimized to prevent pulling historical
    /// data to the client. It works in two phases for each tree level,
    /// executed concurrently:
    /// 1. **Discover**: A `SELECT DISTINCT node_index` query is run for the
    ///    level to find all unique nodes that have ever existed. This is a
    ///    metadata-only query and is very fast.
    /// 2. **Fetch**: For each discovered `node_index`, it executes the highly
    ///    efficient `select_1` query (`... WHERE ... LIMIT 1`) to get the
    ///    single, latest version of that node at or before the target
    ///    checkpoint.
    ///
    /// This strategy minimizes data transfer and leverages Scylla's strengths
    /// for point lookups, ensuring the dump is as fast and efficient as
    /// possible.

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
    /// Optimized: increased batch size to 512 for higher throughput; streams
    /// batches concurrently via join_all.
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

    /// Batch inserts multiple nodes at checkpoint_id.
    /// Optimized: increased batch size to 512 for higher throughput; streams
    /// batches concurrently via join_all.
    pub async fn set_zero_id_merkle_nodes_batch_internal_checkpoint_is_index<Hash: QHashBase>(
        &self,
        session: &Session,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()> {
        const BATCH_SIZE: usize = 512; // Increased for performance; safe assuming typical node sizes.
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i8, i64, i64, Vec<u8>)>> = Vec::new();
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
                        u64_to_i64_exact(n.key.index),
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

        // Parallel deserialization using rayon
        let values: Vec<(i8, i64, i64, [u8; 32])> = data
            .par_chunks(QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE)
            .map(|slice| QMerkleStoreFastZeroNodeSerializer::deserialize_zero_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64))
            .collect();
        self.execute_zero_id_merkle_values(session, &values, batch_size).await
    }

    /// Issue the batched inserts for an already decoded node set.
    ///
    /// Shared by the recording path and the plain one, so both write through
    /// exactly the same statements.
    async fn execute_zero_id_merkle_values(
        &self,
        session: &Session,
        values: &[(i8, i64, i64, [u8; 32])],
        batch_size: usize,
    ) -> anyhow::Result<()> {
        if values.is_empty() {
            return Ok(());
        }

        const CONCURRENCY_LIMIT: usize = 64; // Tuned for typical Scylla clusters

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

    /// Decode the node set without writing anything.
    ///
    /// design-r1 §3 puts the manifest on disk before any hot write, so a crash
    /// can never leave rows that no manifest names.  That means the mutation
    /// set has to be known before execution, which is why decoding is split out
    /// here rather than happening inside the write.  The decoded rows are
    /// carried forward so the blob is parsed exactly once.
    pub fn plan_zero_id_merkle_nodes_fast_serialize<Hash: QHash256Base>(
        &self,
        checkpoint_id: u64,
        data: &[u8],
        sink: &dyn CommitMutationSink,
    ) -> anyhow::Result<ZeroMerkleWritePlan> {
        plan_zero_merkle_nodes::<Hash>(self.physical_table, checkpoint_id, data, sink)
    }

    /// Execute a plan produced by [`Self::plan_zero_id_merkle_nodes_fast_serialize`].
    pub async fn execute_zero_id_merkle_write_plan(
        &self,
        session: &Session,
        plan: ZeroMerkleWritePlan,
    ) -> anyhow::Result<()> {
        if plan.values.is_empty() {
            return Ok(());
        }
        let batch_size = calc_best_batch_size(plan.values.len(), &[256, 128, 64]);
        self.execute_zero_id_merkle_values(session, &plan.values, batch_size)
            .await
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
        self.set_zero_id_merkle_nodes_batch_fast_serialize_with_batch_size_internal::<Hash>(session, checkpoint_id, data, batch_size)
            .await
    }
}

impl ScyllaMerkleNodesZeroPreparedStatements {
    // Consolidated dump: stream leaf level, dedup client-side for latest <=
    // max_checkpoint
    async fn dump_leaves_stream<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        start_index: u64,
        end_index: Option<u64>, // None for full
    ) -> anyhow::Result<HashMap<u64, Hash>> {
        if end_index.is_some() {
            return self
                .dump_leaves_stream_end_index::<Hash>(session, max_checkpoint_id, start_index, end_index.unwrap())
                .await;
        }
        let level_i8 = u8_to_i8_exact(self.tree_height);
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
        let query = format!(
            "SELECT node_index, checkpoint_id, value FROM {}.{} WHERE level = ?",
            self.keyspace, self.table_name
        );
        let mut stream = session.query_iter(query, &(level_i8,)).await?.rows_stream::<(i64, i64, Vec<u8>)>()?;
        let mut output_map = HashMap::new();
        let mut prev_index: Option<i64> = None;
        while let Some(next_row_res) = stream.next().await {
            let (node_index_i64, cp_i64, value) = next_row_res?;
            let node_index = i64_to_u64_exact(node_index_i64); // Assuming utils has i64_to_u64_exact
            if Some(node_index_i64) != prev_index {
                if cp_i64 <= max_cp_i64 {
                    let hash = Hash::from_slice_32bytes(&value)?;

                    output_map.insert(node_index, hash);
                }
                prev_index = Some(node_index_i64);
            }
            // Else skip historical for same index
        }
        Ok(output_map)
    }
    // Consolidated dump: stream leaf level, dedup client-side for latest <=
    // max_checkpoint
    async fn dump_leaves_stream_end_index<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        start_index: u64,
        end_index: u64, // None for full
    ) -> anyhow::Result<HashMap<u64, Hash>> {
        let level_i8 = u8_to_i8_exact(self.tree_height);
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
        let query = format!(
            "SELECT node_index, checkpoint_id, value FROM {}.{} WHERE level = ? AND node_index >= ? AND node_index <= ?",
            self.keyspace, self.table_name
        );
        let mut stream = session // TODO:, make this not i64 or something, it messes up the ranges
            .query_iter(query, &(level_i8, u64_to_i64_exact(start_index), u64_to_i64_exact(end_index)))
            .await?
            .rows_stream::<(i64, i64, Vec<u8>)>()?;
        let mut output_map = HashMap::new();
        let mut prev_index: Option<i64> = None;
        while let Some(next_row_res) = stream.next().await {
            let (node_index_i64, cp_i64, value) = next_row_res?;
            let node_index = i64_to_u64_exact(node_index_i64); // Assuming utils has i64_to_u64_exact
            if Some(node_index_i64) != prev_index {
                if cp_i64 <= max_cp_i64 {
                    let hash = Hash::from_slice_32bytes(&value)?;

                    output_map.insert(node_index, hash);
                }
                prev_index = Some(node_index_i64);
            }
            // Else skip historical for same index
        }
        Ok(output_map)
    }

    pub async fn dump_all_zero_id_merkle_node_leaves_sparse_sub_trees<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<HashMap<u64, Hash>> {
        self.dump_leaves_stream::<Hash>(session, max_checkpoint_id, 0, None).await
    }

    pub async fn dump_all_zero_id_merkle_node_leaves_fast<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<HashMap<u64, Hash>> {
        self.dump_leaves_stream::<Hash>(session, max_checkpoint_id, 0, None).await
    }

    pub async fn dump_all_zero_id_merkle_node_leaves_append_only<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<HashMap<u64, Hash>> {
        let total_leaves = 1u64 << self.tree_height;
        let mut low = 0u64;
        let mut high = total_leaves.saturating_sub(1);
        let mut first_zero_idx = total_leaves;
        while low <= high {
            let mid = low + (high - low) / 2;
            let res = session
                .execute_unpaged(
                    &self.select_1_prepared,
                    (
                        u8_to_i8_exact(self.tree_height),
                        u64_to_i64_exact(mid),
                        convert_checkpoint_id_to_i64(max_checkpoint_id),
                    ),
                )
                .await?;
            let is_present = res.into_rows_result()?.maybe_first_row::<(Vec<u8>,)>()?.is_some();
            if is_present {
                low = mid.saturating_add(1);
            } else {
                first_zero_idx = mid;
                if mid == 0 {
                    break;
                }
                high = mid.saturating_sub(1);
            }
        }
        if first_zero_idx == 0 {
            return Ok(HashMap::new());
        }
        self.dump_leaves_stream::<Hash>(session, max_checkpoint_id, 0, Some(first_zero_idx - 1))
            .await
    }

    pub async fn dump_all_zero_id_merkle_node_leaves_vec<Hash: QDBHashBase>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        strategy: MerkleTreeDumpStrategy,
    ) -> anyhow::Result<Vec<SimpleMerkleNode<Hash>>> {
        let map = match strategy {
            // Use appropriate based on strategy; here assuming sparse as default
            //MerkleTreeDumpStrategy::DumpAllStrategy => self.dump_all_zero_id_merkle_node_leaves_sparse_sub_trees::<Hash>(session,
            // max_checkpoint_id).await?,
            MerkleTreeDumpStrategy::DumpAllStrategy => self.dump_all_zero_id_merkle_node_leaves_fast::<Hash>(session, max_checkpoint_id).await?,
            MerkleTreeDumpStrategy::AppendOnlyTreeStrategy => {
                self.dump_all_zero_id_merkle_node_leaves_append_only::<Hash>(session, max_checkpoint_id)
                    .await?
            } // Add others if defined
        };
        let mut vec: Vec<_> = map
            .into_iter()
            .map(|(index, value)| SimpleMerkleNode {
                key: SimpleMerkleNodeKey {
                    level: self.tree_height,
                    index,
                },
                value,
            })
            .collect();
        vec.sort_by_key(|n| n.key.index); // Ensure ordered if needed
        Ok(vec)
    }
}

#[cfg(test)]
mod recording_tests {
    use super::*;
    use crate::rollback::{
        CollectingMutationSink, RecordedOperation, describe_existing_key, zero_merkle_node_key,
    };
    use parth_core::PHash;

    /// 41 bytes per node: level, little-endian index, 32-byte value.
    fn blob(nodes: &[(u8, u64)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(nodes.len() * QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE);
        for (level, index) in nodes {
            out.push(*level);
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(&[7u8; 32]);
        }
        out
    }

    #[test]
    fn every_row_that_will_be_written_is_recorded_exactly_once() {
        // The property the whole typed boundary rests on.  If the sink saw fewer
        // rows than the plan writes, rollback would delete less than the commit
        // wrote and leave ghost rows behind at a reused height.
        let nodes = [(0u8, 0u64), (0, 1), (1, 0), (2, 0), (24, 0)];
        let sink = CollectingMutationSink::new();
        let plan = plan_zero_merkle_nodes::<PHash>(
            ScyllaPhysicalTableId::GlobalUserTree,
            41,
            &blob(&nodes),
            &sink,
        )
        .unwrap();
        assert_eq!(plan.row_count(), nodes.len());
        let records = sink.take();
        assert_eq!(records.len(), plan.row_count());
        let checkpoint = CheckpointId::try_new(41).unwrap();
        for (record, (level, index)) in records.iter().zip(nodes) {
            assert_eq!(record.operation(), RecordedOperation::Put);
            assert_eq!(
                record.physical_table(),
                ScyllaPhysicalTableId::GlobalUserTree
            );
            let expected = describe_existing_key(
                &zero_merkle_node_key(
                    ScyllaPhysicalTableId::GlobalUserTree,
                    level,
                    index,
                    checkpoint,
                )
                .unwrap(),
            );
            assert_eq!(record.locator_bytes(), expected.locator_bytes());
        }
    }

    #[test]
    fn an_empty_node_set_records_nothing_and_writes_nothing() {
        let sink = CollectingMutationSink::new();
        let plan =
            plan_zero_merkle_nodes::<PHash>(ScyllaPhysicalTableId::GlobalUserTree, 1, &[], &sink)
                .unwrap();
        assert_eq!(plan.row_count(), 0);
        assert!(sink.is_empty());
    }

    #[test]
    fn a_malformed_blob_is_refused_before_anything_is_recorded() {
        // Recording a partial set would be worse than recording none: the
        // manifest would claim a row count the commit never wrote.
        let sink = CollectingMutationSink::new();
        let mut truncated = blob(&[(0, 0)]);
        truncated.pop();
        assert!(
            plan_zero_merkle_nodes::<PHash>(
                ScyllaPhysicalTableId::GlobalUserTree,
                1,
                &truncated,
                &sink,
            )
            .is_err()
        );
        assert!(sink.is_empty());
    }

    #[test]
    fn each_zero_id_tree_records_against_its_own_table() {
        let nodes = [(3u8, 9u64)];
        for physical in [
            ScyllaPhysicalTableId::GlobalUserTree,
            ScyllaPhysicalTableId::GlobalCheckpointTree,
            ScyllaPhysicalTableId::UserRegistrationTree,
            ScyllaPhysicalTableId::GlobalContractTree,
        ] {
            let sink = CollectingMutationSink::new();
            plan_zero_merkle_nodes::<PHash>(physical, 5, &blob(&nodes), &sink).unwrap();
            let records = sink.take();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].physical_table(), physical);
        }
    }

    #[test]
    fn a_table_outside_the_zero_id_family_is_refused() {
        let sink = CollectingMutationSink::new();
        assert!(
            plan_zero_merkle_nodes::<PHash>(
                ScyllaPhysicalTableId::UserLeaf,
                1,
                &blob(&[(0, 0)]),
                &sink,
            )
            .is_err()
        );
    }
}
