use std::{collections::HashMap, sync::Arc};

use anyhow::Context;
use dashmap::DashMap;
use futures::{future::join_all, stream, StreamExt, TryStreamExt};
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::{
        db::table::QDatabaseTableRoutingKey,
        hash::{
            fast_node_serializer::{QMerkleStoreFastZeroNodeSerializer, QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE},
            merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey},
        },
    },
    protocol::core_types::{QDBHashBase, QHash256Base, QHashBase},
};
use psy_node_core::store::traits::core_db::MerkleTreeDumpStrategy;
use rayon::{iter::ParallelIterator, slice::ParallelSlice};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{batch::Batch, prepared::PreparedStatement, Statement},
};

use crate::utils::{
    calc_best_batch_size, convert_checkpoint_id_to_i64, generate_batch_prepared_statement, i64_to_u64_exact, u64_to_i64_exact, u8_to_i8_exact,
};

#[derive(Clone)]
pub struct ScyllaMerkleNodesZeroPreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,
    pub select_1_statement: Statement,
    pub select_1_prepared: Arc<PreparedStatement>,
    pub insert_batch_serialized_256_prepared: Arc<Batch>,
    pub insert_batch_serialized_128_prepared: Arc<Batch>,
    pub insert_batch_serialized_64_prepared: Arc<Batch>,
    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
    pub tree_height: u8,
}

impl ScyllaMerkleNodesZeroPreparedStatements {
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
    pub async fn select_zero_id_merkle_node_max_checkpoint_internal<Hash: QDBHashBase, Hasher: MerkleZeroHasher<Hash>>(
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
            Some(row) => Ok(Hash::from_slice_32bytes(&row.0)?),
            None => Ok(Hasher::get_zero_hash((self.tree_height - key.level) as usize)),
        }
    }

    pub async fn select_many_zero_id_merkle_nodes_max_checkpoint_internal<Hash: QDBHashBase, Hasher: MerkleZeroHasher<Hash>>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        const CONCURRENT_LIMIT: usize = 2048; // Boosted from 512 based on benchmarks
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

    pub async fn set_zero_id_merkle_nodes_batch_internal<Hash: QHashBase>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()> {
        const BATCH_SIZE: usize = 1024; // Increased from 512 for higher throughput
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
        const CONCURRENCY_LIMIT: usize = 2048; // Boosted
        let values: Vec<(i8, i64, i64, [u8; 32])> = data
            .par_chunks(QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE)
            .map(|slice| QMerkleStoreFastZeroNodeSerializer::deserialize_zero_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64))
            .collect();
        let batch_prepared = match batch_size {
            256 => &self.insert_batch_serialized_256_prepared,
            128 => &self.insert_batch_serialized_128_prepared,
            64 => &self.insert_batch_serialized_64_prepared,
            _ => unreachable!(),
        };
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
        self.set_zero_id_merkle_nodes_batch_fast_serialize_with_batch_size_internal::<Hash>(session, checkpoint_id, data, batch_size)
            .await
    }

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
            }
            // Add others if defined
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

    // Removed unused helpers: sparse_dump_recursive, scan_tree_level_caps,
    // dump_tree_span, etc. Removed select_optional_zero_id_merkle_node_internal
    // (inlined if needed)
}
