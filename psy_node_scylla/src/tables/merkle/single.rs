use std::sync::Arc;
use rayon::slice::{ParallelSlice};
use rayon::iter::ParallelIterator;
use anyhow::Context;
use futures::{future::join_all, stream, StreamExt, TryStreamExt};

use async_trait::async_trait;
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::{
        db::table::QDatabaseTableRoutingKey,
        hash::{fast_node_serializer::{QMerkleStoreFastSingleNodeSerializer, QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE}, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}},
    },
    protocol::core_types::{QHash256Base, QHashBase},
};
use scylla::{
    client::session::Session,
    statement::{batch::Batch, prepared::PreparedStatement, Statement},
};

use crate::table_creator::create_table_if_not_exists;
use crate::utils::{calc_best_batch_size, generate_batch_prepared_statement};
use psy_node_core::store::typed::CheckpointId;
use crate::rollback::{
    CommitMutationSink, ScyllaPhysicalTableId, physical_table_by_name, record_single_merkle_put,
};
use crate::{
    tables::traits::ScyllaStandardPreparedTableStatements,
    utils::{convert_checkpoint_id_to_i64, u64_to_i64_exact, u8_to_i8_exact},
};

#[derive(Clone)]
pub struct ScyllaMerkleNodesPreparedStatements {
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
    /// Which of the two single-id Merkle tables this adapter serves.
    ///
    /// Required, not optional: a single-id table missing from the typed registry
    /// would have its writes go unrecorded, and rollback would not know they
    /// happened.  Startup is the only place that failure is visible.
    pub physical_table: ScyllaPhysicalTableId,
}

/// Decode a fast-serialized single-id node set and hand every row to `sink`.
///
/// Same contract as the zero-id writer: design-r1 §3 needs the mutation set
/// before any hot write, so decoding is separate from execution and the blob is
/// parsed once.
pub fn plan_single_merkle_nodes<Hash: QHash256Base>(
    physical_table: ScyllaPhysicalTableId,
    checkpoint_id: u64,
    data: &[u8],
    sink: &dyn CommitMutationSink,
) -> anyhow::Result<SingleMerkleWritePlan> {
    let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
    if data.len() % QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE != 0 {
        anyhow::bail!("Data length is not a multiple of single id node size");
    }
    let values: Vec<(i64, i8, i64, i64, [u8; 32])> = data
        .par_chunks(QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE)
        .map(|slice| {
            QMerkleStoreFastSingleNodeSerializer::deserialize_single_id_node_signed_insert_tuple::<Hash>(
                slice,
                checkpoint_i64,
            )
        })
        .collect();
    let checkpoint = CheckpointId::try_new(checkpoint_id)?;
    for (tree_id, level, node_index, _, _) in &values {
        record_single_merkle_put(
            sink,
            physical_table,
            u64::try_from(*tree_id)?,
            u8::try_from(*level)?,
            u64::try_from(*node_index)?,
            checkpoint,
        )?;
    }
    Ok(SingleMerkleWritePlan { values })
}

/// A decoded single-id Merkle node set, recorded and ready to write.
pub struct SingleMerkleWritePlan {
    values: Vec<(i64, i8, i64, i64, [u8; 32])>,
}

impl SingleMerkleWritePlan {
    /// How many physical rows this plan will write.
    pub fn row_count(&self) -> usize {
        self.values.len()
    }
}

impl ScyllaMerkleNodesPreparedStatements {
    pub fn plan_single_id_merkle_nodes_fast_serialize<Hash: QHash256Base>(
        &self,
        checkpoint_id: u64,
        data: &[u8],
        sink: &dyn CommitMutationSink,
    ) -> anyhow::Result<SingleMerkleWritePlan> {
        plan_single_merkle_nodes::<Hash>(self.physical_table, checkpoint_id, data, sink)
    }

    pub async fn execute_single_id_merkle_write_plan(
        &self,
        session: &Session,
        plan: SingleMerkleWritePlan,
    ) -> anyhow::Result<()> {
        if plan.values.is_empty() {
            return Ok(());
        }
        let batch_size = calc_best_batch_size(plan.values.len(), &[256, 128, 64]);
        self.execute_single_id_merkle_values(session, &plan.values, batch_size)
            .await
    }

    pub async fn new_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(&format!(
            "INSERT INTO {}.{} (tree_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?)",
            keyspace, table_name
        ));
        let insert_prepared = session.prepare(insert_1_statement.clone()).await?;
        let select_1_statement = Statement::new(&format!(
            "SELECT value FROM {}.{} WHERE tree_id = ? AND level = ? AND node_index = ? AND checkpoint_id <= ? LIMIT 1",
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
            physical_table: physical_table_by_name(table_name).ok_or_else(|| {
                anyhow::anyhow!(
                    "single-id Merkle table {table_name:?} is not in the typed registry, so its \
                     writes could not be recorded for rollback"
                )
            })?,
        })
    }
    pub async fn create_table(session: Arc<Session>, keyspace: &str, table_name: &str, _table_key: QDatabaseTableRoutingKey) -> anyhow::Result<()> {
        create_table_if_not_exists(
                &session,
                keyspace,
                table_name,
                &format!(
                    "CREATE TABLE IF NOT EXISTS {}.{} (
                    tree_id BIGINT,
                    level TINYINT,
                    node_index BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((tree_id), level, node_index, checkpoint_id)
                ) WITH CLUSTERING ORDER BY (level ASC, node_index ASC, checkpoint_id DESC)",
                    keyspace, table_name
                ),
            )
            .await?;
        Ok(())
    }
    pub async fn new_create_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::create_table(session.clone(), keyspace, table_name, table_key).await?;
        Self::new_from_session(session, keyspace, table_name, table_key).await
    }
}

#[async_trait]
impl ScyllaStandardPreparedTableStatements for ScyllaMerkleNodesPreparedStatements {
    async fn create_table_standard(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::new_create_from_session(session, keyspace, table_name, table_key).await
    }

    async fn prepare_only_standard(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::new_from_session(session, keyspace, table_name, table_key).await
    }
}


impl ScyllaMerkleNodesPreparedStatements {
    pub async fn select_single_id_merkle_node_max_checkpoint_internal<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        let res = session
            .execute_unpaged(
                &self.select_1_prepared,
                (
                    u64_to_i64_exact(tree_id),
                    u8_to_i8_exact(key.level),
                    u64_to_i64_exact(key.index),
                    convert_checkpoint_id_to_i64(checkpoint_id),
                ),
            )
            .await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => Ok(Hash::from_bytes(&row.0)?),
            None => Ok(Hasher::get_zero_hash((tree_height - key.level) as usize)), // Return zero hash if not found
        }
    }

    pub async fn select_many_single_id_merkle_nodes_max_checkpoint_internal<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        const CONCURRENT_LIMIT: usize = 256; // Batch concurrent queries
        let mut results = Vec::with_capacity(keys.len());
        for chunk in keys.chunks(CONCURRENT_LIMIT) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let prep = self.select_1_prepared.clone();
                    let tree_id_i64 = u64_to_i64_exact(tree_id);
                    let level_i8 = u8_to_i8_exact(key.level);
                    let index_i64 = u64_to_i64_exact(key.index);
                    let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
                    async move {
                        let res = session.execute_unpaged(&prep, (tree_id_i64, level_i8, index_i64, max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                            Hash::from_bytes(&row.0)
                        } else {
                            // Assume reverse_level = level for simplicity; adjust if tree height known
                            Ok(Hasher::get_zero_hash((tree_height - key.level) as usize))
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
    pub async fn insert_single_id_merkle_node_internal(
        &self,
        session: &Session,
        checkpoint_id: u64,
        tree_id: u64,
        key: SimpleMerkleNodeKey,
        value: &[u8],
    ) -> anyhow::Result<()> {
        session
            .execute_unpaged(
                &self.insert_1_prepared,
                (
                    u64_to_i64_exact(tree_id),
                    u8_to_i8_exact(key.level),
                    u64_to_i64_exact(key.index),
                    u64_to_i64_exact(checkpoint_id),
                    value,
                ),
            )
            .await?;
        Ok(())
    }
    pub async fn set_single_id_merkle_nodes_batch_internal<Hash: QHashBase>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        tree_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()> {
        const BATCH_SIZE: usize = 256; // Safe batch size to avoid payload limits
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, level, node_index, checkpoint_id, value
        let mut value_list: Vec<Vec<(i64, i8, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in nodes.chunks(BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((
                        u64_to_i64_exact(tree_id),
                        u8_to_i8_exact(n.key.level),
                        u64_to_i64_exact(n.key.index),
                        checkpoint_id as i64,
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


impl ScyllaMerkleNodesPreparedStatements {

    async fn set_single_id_merkle_nodes_batch_fast_serialize_with_batch_size_internal<Hash: QHash256Base>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        data: &[u8],
        batch_size: usize,
    ) -> anyhow::Result<()> {
        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        if data.len() % QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE != 0 {
            anyhow::bail!("Data length is not a multiple of double id node size");
        }
        let num_nodes = data.len() / QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE;

        if num_nodes == 0 {
            return Ok(());
        }

        // Parallel deserialization using rayon
        let values: Vec<(i64, i8, i64, i64, [u8; 32])> = data
            .par_chunks(QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE)
            .map(|slice| {
                QMerkleStoreFastSingleNodeSerializer::deserialize_single_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64)
            })
            .collect();
        self.execute_single_id_merkle_values(session, &values, batch_size).await
    }

    /// Issue the batched inserts for an already decoded node set.
    ///
    /// Shared by the recording path and the plain one, so both write through the
    /// same statements.
    async fn execute_single_id_merkle_values(
        &self,
        session: &Session,
        values: &[(i64, i8, i64, i64, [u8; 32])],
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
     
    pub async fn set_single_id_merkle_nodes_batch_fast_serialize<Hash: QHash256Base>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()> {
        if data.len() % QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE != 0 {
            anyhow::bail!("Data length is not a multiple of single id node size");
        }
        let num_nodes = data.len() / QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE;
        if num_nodes == 0 {
            return Ok(());
        }
        
        let batch_size = calc_best_batch_size(num_nodes, &[256, 128, 64]);
        self.set_single_id_merkle_nodes_batch_fast_serialize_with_batch_size_internal::<Hash>(session, checkpoint_id, data, batch_size).await

    }
}
#[cfg(test)]
mod recording_tests {
    use super::*;
    use crate::rollback::{
        CollectingMutationSink, RecordedOperation, describe_existing_key, single_merkle_node_key,
    };
    use parth_core::PHash;

    /// 49 bytes per node: little-endian tree id, level, little-endian index,
    /// 32-byte value.
    fn blob(nodes: &[(u64, u8, u64)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(nodes.len() * QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE);
        for (tree_id, level, index) in nodes {
            out.extend_from_slice(&tree_id.to_le_bytes());
            out.push(*level);
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(&[3u8; 32]);
        }
        out
    }

    #[test]
    fn every_row_that_will_be_written_is_recorded_exactly_once() {
        let nodes = [(1u64, 0u8, 0u64), (1, 1, 0), (2, 0, 5), (2, 3, 1)];
        let sink = CollectingMutationSink::new();
        let plan = plan_single_merkle_nodes::<PHash>(
            ScyllaPhysicalTableId::ContractFunctionTree,
            77,
            &blob(&nodes),
            &sink,
        )
        .unwrap();
        assert_eq!(plan.row_count(), nodes.len());
        let records = sink.take();
        assert_eq!(records.len(), plan.row_count());
        let checkpoint = CheckpointId::try_new(77).unwrap();
        for (record, (tree_id, level, index)) in records.iter().zip(nodes) {
            assert_eq!(record.operation(), RecordedOperation::Put);
            let expected = describe_existing_key(
                &single_merkle_node_key(
                    ScyllaPhysicalTableId::ContractFunctionTree,
                    tree_id,
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
    fn nodes_from_different_subtrees_never_share_a_locator() {
        // One blob can carry nodes of many trees, so the tree id has to reach
        // the locator or a rollback would collapse two subtrees into one.
        let nodes = [(1u64, 0u8, 0u64), (2, 0, 0), (3, 0, 0)];
        let sink = CollectingMutationSink::new();
        plan_single_merkle_nodes::<PHash>(
            ScyllaPhysicalTableId::UserContractTree,
            9,
            &blob(&nodes),
            &sink,
        )
        .unwrap();
        let locators: std::collections::BTreeSet<_> = sink
            .take()
            .into_iter()
            .map(|record| record.locator_bytes().to_vec())
            .collect();
        assert_eq!(locators.len(), nodes.len());
    }

    #[test]
    fn a_malformed_blob_is_refused_before_anything_is_recorded() {
        let sink = CollectingMutationSink::new();
        let mut truncated = blob(&[(1, 0, 0)]);
        truncated.pop();
        assert!(
            plan_single_merkle_nodes::<PHash>(
                ScyllaPhysicalTableId::UserContractTree,
                1,
                &truncated,
                &sink,
            )
            .is_err()
        );
        assert!(sink.is_empty());
    }

    #[test]
    fn a_table_outside_the_single_id_family_is_refused() {
        let sink = CollectingMutationSink::new();
        assert!(
            plan_single_merkle_nodes::<PHash>(
                ScyllaPhysicalTableId::GlobalUserTree,
                1,
                &blob(&[(1, 0, 0)]),
                &sink,
            )
            .is_err()
        );
    }
}
