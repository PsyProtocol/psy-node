use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use futures::{future::join_all, stream, StreamExt, TryStreamExt};
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::{
        db::table::QDatabaseTableRoutingKey,
        hash::{
            fast_node_serializer::{QMerkleStoreFastDoubleNodeSerializer, QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE},
            merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey},
            merkle_store_key::QMerkleStoreDoubleIdNode,
        },
    },
    protocol::core_types::{Q256BitHash, QHash256Base, QHashBase},
};
use rayon::{
    iter::{IntoParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use scylla::{
    client::session::Session,
    statement::{
        batch::{Batch, BatchType},
        prepared::PreparedStatement,
        Statement,
    },
};

use crate::{
    tables::traits::ScyllaStandardPreparedTableStatements,
    utils::{calc_best_batch_size, convert_checkpoint_id_to_i64, generate_batch_prepared_statement, u64_to_i64_exact, u8_to_i8_exact},
};


#[derive(Clone)]
pub struct ScyllaDoubleMerkleNodesPreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,
    //pub insert_batch_serialized_512_prepared: Arc<Batch>,
    pub insert_batch_serialized_256_prepared: Arc<Batch>,
    pub insert_batch_serialized_128_prepared: Arc<Batch>,
    pub insert_batch_serialized_64_prepared: Arc<Batch>,
    //pub insert_batch_serialized_32_prepared: Arc<Batch>,
    pub select_1_statement: Statement,
    pub select_1_prepared: Arc<PreparedStatement>,
    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
}

impl ScyllaDoubleMerkleNodesPreparedStatements {
    pub async fn new_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(&format!(
            "INSERT INTO {}.{} (tree_id, tree_sub_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?, ?)",
            keyspace, table_name
        ));
        let insert_1_prepared = session.prepare(insert_1_statement.clone()).await?;
        let select_1_statement = Statement::new(&format!(
            "SELECT value FROM {}.{} WHERE tree_id = ? AND tree_sub_id = ? AND level = ? AND node_index = ? AND checkpoint_id <= ? LIMIT 1",
            keyspace, table_name
        ));
        let select_1_prepared = session.prepare(select_1_statement.clone()).await?;

        Ok(Self {
            //insert_batch_serialized_512_prepared: Arc::new(generate_batch_prepared_statement(&session, &insert_1_statement, 512).await?),
            insert_batch_serialized_256_prepared: Arc::new(generate_batch_prepared_statement(&session, &insert_1_prepared, 256).await?),
            insert_batch_serialized_128_prepared: Arc::new(generate_batch_prepared_statement(&session, &insert_1_prepared, 128).await?),
            insert_batch_serialized_64_prepared: Arc::new(generate_batch_prepared_statement(&session, &insert_1_prepared, 64).await?),
            //insert_batch_serialized_32_prepared: Arc::new(generate_batch_prepared_statement(&session, &insert_1_statement, 32).await?),
            insert_1_statement,
            insert_1_prepared: Arc::new(insert_1_prepared),
            select_1_statement,
            select_1_prepared: Arc::new(select_1_prepared),
            table_key,
            keyspace: keyspace.to_string(),
            table_name: table_name.to_string(),
        })
    }
    pub async fn create_table(session: Arc<Session>, keyspace: &str, table_name: &str, _table_key: QDatabaseTableRoutingKey) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {}.{} (
                    tree_id BIGINT,
                    tree_sub_id BIGINT,
                    level TINYINT,
                    node_index BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((tree_id, tree_sub_id), level, node_index, checkpoint_id)
                ) WITH CLUSTERING ORDER BY (level ASC, node_index ASC, checkpoint_id DESC)",
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
    ) -> anyhow::Result<Self> {
        Self::create_table(session.clone(), keyspace, table_name, table_key).await?;
        Self::new_from_session(session, keyspace, table_name, table_key).await
    }
}

#[async_trait]
impl ScyllaStandardPreparedTableStatements for ScyllaDoubleMerkleNodesPreparedStatements {
    async fn create_table_standard(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::new_create_from_session(session, keyspace, table_name, table_key).await
    }
}

impl ScyllaDoubleMerkleNodesPreparedStatements {
    pub async fn set_double_id_merkle_nodes_batch_from_fast_serialized_data_simple<Hash: Q256BitHash>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        if data.len() % QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE != 0 {
            anyhow::bail!("Data length is not a multiple of double id node size");
        }
        let num_nodes = data.len() / QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;

        if num_nodes == 0 {
            return Ok(());
        }
        let remainder_count = num_nodes % 256;
        let first_batch_size = if remainder_count == 0 { 256 } else { remainder_count };
        let num_batches = num_nodes / 256 + if remainder_count == 0 { 0 } else { 1 };
        let mut node_index = 0;
        // first do a batch with the remainder amou

        let mut batch: Batch = Default::default();
        let mut batch_index = 0;
        if first_batch_size != 256 {
            for _ in 0..first_batch_size {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let mut values: Vec<(i64, i64, i8, i64, i64, [u8; 32])> = Vec::with_capacity(first_batch_size);
            for i in 0..first_batch_size {
                let start = (i + node_index) * QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
                let end = start + QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
                let slice = &data[start..end];
                let tuple = QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64);
                values.push(tuple);
            }
            node_index += first_batch_size;
            session.batch(&batch, values).await?;
            batch_index += 1;
        }
        for _ in first_batch_size..256 {
            batch.append_statement(self.insert_1_statement.clone());
        }
        for _ in batch_index..num_batches {
            let mut values: Vec<(i64, i64, i8, i64, i64, [u8; 32])> = Vec::with_capacity(256);
            for i in 0..256 {
                let start = (i + node_index) * QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
                let end = start + QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
                let slice = &data[start..end];
                let tuple = QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64);
                values.push(tuple);
            }
            node_index += 256;
            session.batch(&batch, values).await?;
        }

        Ok(())
    }
    pub async fn set_double_id_merkle_nodes_batch_256_from_fast_serialized_data<Hash: Q256BitHash>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        if data.len() % QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE != 0 {
            anyhow::bail!("Data length is not a multiple of double id node size");
        }
        let num_nodes = data.len() / QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;

        if num_nodes == 0 {
            return Ok(());
        }
        let remainder_count = num_nodes % 256;
        let first_batch_size = if remainder_count == 0 { 256 } else { remainder_count };
        let num_batches = num_nodes / 256 + if remainder_count == 0 { 0 } else { 1 };
        let mut node_index = 0;
        // first do a batch with the remainder amou

        let mut batch: Batch = Default::default();
        let mut batch_index = 0;
        if first_batch_size != 256 {
            for _ in 0..first_batch_size {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let mut values: Vec<(i64, i64, i8, i64, i64, [u8; 32])> = Vec::with_capacity(first_batch_size);
            for i in 0..first_batch_size {
                let start = (i + node_index) * QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
                let end = start + QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
                let slice = &data[start..end];
                let tuple = QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64);
                values.push(tuple);
            }
            node_index += first_batch_size;
            session.batch(&batch, values).await?;
            batch_index += 1;
        }
        for _ in first_batch_size..256 {
            batch.append_statement(self.insert_1_statement.clone());
        }
        for _ in batch_index..num_batches {
            let mut values: Vec<(i64, i64, i8, i64, i64, [u8; 32])> = Vec::with_capacity(256);
            for i in 0..256 {
                let start = (i + node_index) * QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
                let end = start + QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
                let slice = &data[start..end];
                let tuple = QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64);
                values.push(tuple);
            }
            node_index += 256;
            session.batch(&batch, values).await?;
        }

        Ok(())
    }

    pub async fn set_double_id_merkle_nodes_batch_g_internal_fast_v2<Hash: QHash256Base>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        if data.len() % QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE != 0 {
            anyhow::bail!("Data length is not a multiple of double id node size");
        }
        let num_nodes = data.len() / QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;

        if num_nodes == 0 {
            return Ok(());
        }
        let remainder_count = num_nodes % 256;
        let last_batch_size = if remainder_count == 0 { 256 } else { remainder_count };
        let num_batches = num_nodes / 256 + if remainder_count == 0 { 0 } else { 1 };

        let ranges: Vec<(usize, usize, usize)> = (0..num_batches)
            .map(|batch_index| {
                let start_index = batch_index * 256;
                let end_index = if batch_index == num_batches - 1 {
                    start_index + last_batch_size
                } else {
                    start_index + 256
                };
                (start_index, end_index, end_index - start_index)
            })
            .collect();

        let futures: Vec<_> = ranges
            .into_iter()
            .map(|(start_index, end_index, count)| async move {
                let mut values: Vec<(i64, i64, i8, i64, i64, [u8; 32])> = Vec::with_capacity(count);
                for i in start_index..end_index {
                    let start = i * QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
                    let end = start + QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
                    let slice = &data[start..end];
                    let tuple = QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64);
                    values.push(tuple);
                }
                if count == 256 {
                    session.batch(&self.insert_batch_serialized_256_prepared, values).await
                } else {
                    let mut batch: Batch = Default::default();
                    for _ in 0..count {
                        batch.append_statement(self.insert_1_statement.clone());
                    }
                    session.batch(&batch, values).await
                }
            })
            .collect();
        let results = join_all(futures).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }

    pub async fn set_double_id_merkle_nodes_batch_g_internal_fast_v3<Hash: QHash256Base>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        if data.len() % QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE != 0 {
            anyhow::bail!("Data length is not a multiple of double id node size");
        }
        let num_nodes = data.len() / QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;

        if num_nodes == 0 {
            return Ok(());
        }
        let remainder_count = num_nodes % 256;
        let last_batch_size = if remainder_count == 0 { 256 } else { remainder_count };
        let num_batches = num_nodes / 256 + if remainder_count == 0 { 0 } else { 1 };

        let ranges: Vec<(usize, usize, usize)> = (0..num_batches)
            .map(|batch_index| {
                let start_index = batch_index * 256;
                let end_index = if batch_index == num_batches - 1 {
                    start_index + last_batch_size
                } else {
                    start_index + 256
                };
                (start_index, end_index, end_index - start_index)
            })
            .collect();

        let futures: Vec<_> = ranges
            .into_iter()
            .map(|(start_index, end_index, count)| async move {
                let mut values: Vec<(i64, i64, i8, i64, i64, [u8; 32])> = Vec::with_capacity(count);
                for i in start_index..end_index {
                    let start = i * QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
                    let end = start + QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
                    let slice = &data[start..end];
                    let tuple = QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64);
                    values.push(tuple);
                }
                if count == 256 {
                    session.batch(&self.insert_batch_serialized_256_prepared, values).await
                } else {
                    let mut batch: Batch = Default::default();
                    for _ in 0..count {
                        batch.append_statement(self.insert_1_statement.clone());
                    }
                    session.batch(&batch, values).await
                }
            })
            .collect();
        let results = join_all(futures).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }

    pub async fn set_double_id_merkle_nodes_batch_g_internal<Hash: QHash256Base>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        nodes: &[QMerkleStoreDoubleIdNode<Hash>],
        batch_size: usize,
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let mut value_list: Vec<Vec<(i64, i64, i8, i64, i64, [u8; 32])>> = Vec::new();
        for chunk in nodes.chunks(batch_size) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((
                        u64_to_i64_exact(n.key.tree_id),
                        u64_to_i64_exact(n.key.tree_sub_id),
                        u8_to_i8_exact(n.key.level),
                        u64_to_i64_exact(n.key.index),
                        convert_checkpoint_id_to_i64(checkpoint_id),
                        n.value.into_owned_32bytes(),
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
    pub async fn set_double_id_merkle_nodes_batch_internal<Hash: QHashBase>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()> {
        const BATCH_SIZE: usize = 256; // Safe batch size to avoid payload limits
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let mut value_list: Vec<Vec<(i64, i64, i8, i64, i64, Vec<u8>)>> = Vec::new();
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
                        u64_to_i64_exact(tree_sub_id),
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
    pub async fn select_double_id_merkle_node_max_checkpoint_internal<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        tree_secondary_id: u64,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        let res = session
            .execute_unpaged(
                &self.select_1_prepared,
                (
                    u64_to_i64_exact(tree_id),
                    u64_to_i64_exact(tree_secondary_id),
                    u8_to_i8_exact(key.level),
                    u64_to_i64_exact(key.index),
                    convert_checkpoint_id_to_i64(checkpoint_id),
                ),
            )
            .await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => {
                if row.0.len() == Hash::get_fixed_size() {
                    Ok(Hash::from_bytes(&row.0)?)
                } else {
                    Ok(Hasher::get_zero_hash((tree_height - key.level) as usize))
                }
            }
            None => Ok(Hasher::get_zero_hash((tree_height - key.level) as usize)),
        }
    }

    pub async fn select_many_double_id_merkle_nodes_max_checkpoint_internal<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        const CONCURRENT_LIMIT: usize = 512; // Batch concurrent queries
        let mut results = Vec::with_capacity(keys.len());
        for chunk in keys.chunks(CONCURRENT_LIMIT) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let prep = self.select_1_prepared.clone();
                    let tree_id_i64 = u64_to_i64_exact(tree_id);
                    let tree_sub_id_i64 = u64_to_i64_exact(tree_sub_id);
                    let level_i8 = u8_to_i8_exact(key.level);
                    let index_i64 = u64_to_i64_exact(key.index);
                    let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
                    async move {
                        let res = session
                            .execute_unpaged(&prep, (tree_id_i64, tree_sub_id_i64, level_i8, index_i64, max_cp_i64))
                            .await?;
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
    pub async fn insert_double_id_merkle_node_internal(
        &self,
        session: &Session,
        checkpoint_id: u64,
        tree_id: u64,
        tree_secondary_id: u64,
        key: SimpleMerkleNodeKey,
        value: &[u8],
    ) -> anyhow::Result<()> {
        session
            .execute_unpaged(
                &self.insert_1_prepared,
                (
                    u64_to_i64_exact(tree_id),
                    u64_to_i64_exact(tree_secondary_id),
                    u8_to_i8_exact(key.level),
                    u64_to_i64_exact(key.index),
                    convert_checkpoint_id_to_i64(checkpoint_id),
                    value,
                ),
            )
            .await?;
        Ok(())
    }
}


impl ScyllaDoubleMerkleNodesPreparedStatements {

    async fn set_double_id_merkle_nodes_batch_fast_serialize_with_batch_size_internal<Hash: QHash256Base>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        data: &[u8],
        batch_size: usize,
    ) -> anyhow::Result<()> {
        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        if data.len() % QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE != 0 {
            anyhow::bail!("Data length is not a multiple of double id node size");
        }
        let num_nodes = data.len() / QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;

        if num_nodes == 0 {
            return Ok(());
        }

        const CONCURRENCY_LIMIT: usize = 64; // Tuned for typical Scylla clusters

        // Parallel deserialization using rayon
        let values: Vec<(i64, i64, i8, i64, i64, [u8; 32])> = data
            .par_chunks(QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE)
            .map(|slice| QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64))
            .collect();

        if batch_size != 64 && batch_size != 128 && batch_size != 256 {
            anyhow::bail!("Invalid batch size, must be one of 64, 128, or 256");
        }
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
    pub async fn set_double_id_merkle_nodes_batch_fast_serialize<Hash: QHash256Base>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let num_nodes = data.len() / QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
        
        self.set_double_id_merkle_nodes_batch_fast_serialize_with_batch_size_internal::<Hash>(
            session,
            checkpoint_id,
            data,
            calc_best_batch_size(num_nodes, &[256, 128, 64]),
        )
        .await
    }
}


impl ScyllaDoubleMerkleNodesPreparedStatements {
    // Add this to your imports

    // ... inside the ScyllaDoubleMerkleNodesPreparedStatements impl

    pub async fn set_double_id_merkle_nodes_batch_g_internal_fast_v5_grok_3_with_batch_size<Hash: QHash256Base>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        data: &[u8],
        batch_size: usize,
    ) -> anyhow::Result<()> {
        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        if data.len() % QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE != 0 {
            anyhow::bail!("Data length is not a multiple of double id node size");
        }
        let num_nodes = data.len() / QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;

        if num_nodes == 0 {
            return Ok(());
        }

        const CONCURRENCY_LIMIT: usize = 64; // Tuned for typical Scylla clusters

        // Parallel deserialization using rayon
        let values: Vec<(i64, i64, i8, i64, i64, [u8; 32])> = data
            .par_chunks(QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE)
            .map(|slice| QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64))
            .collect();

        if batch_size != 64 && batch_size != 128 && batch_size != 256 {
            anyhow::bail!("Invalid batch size, must be one of 64, 128, or 256");
        }
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
    pub async fn set_double_id_merkle_nodes_batch_g_internal_fast_v5_grok_3<Hash: QHash256Base>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let num_nodes = data.len() / QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
        
        self.set_double_id_merkle_nodes_batch_g_internal_fast_v5_grok_3_with_batch_size::<Hash>(
            session,
            checkpoint_id,
            data,
            calc_best_batch_size(num_nodes, &[256, 128, 64]),
        )
        .await
        /*
        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        if data.len() % QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE != 0 {
            anyhow::bail!("Data length is not a multiple of double id node size");
        }
        let num_nodes = data.len() / QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;

        if num_nodes == 0 {
            return Ok(());
        }

        const BATCH_SIZES: &[usize] = &[256, 128, 64, 32];
        const CONCURRENCY_LIMIT: usize = 64; // Tuned for typical Scylla clusters

        // Select the largest batch size that divides num_nodes with minimal remainder
        let batch_size = BATCH_SIZES.iter()
            .find(|&&size| num_nodes >= size && (num_nodes % size == 0 || num_nodes / size >= 1))
            .unwrap_or(&32);
        let num_batches = (num_nodes + batch_size - 1) / batch_size;

        // Parallel deserialization using rayon
        let values: Vec<(i64, i64, i8, i64, i64, [u8; 32])> = data
            .par_chunks(QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE)
            .map(|slice| {
                QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64)
            })
            .collect();

        // Map batch size to pre-prepared batch
        let batch_prepared = match batch_size {
            // 512 => &self.insert_batch_serialized_512_prepared,
            256 => &self.insert_batch_serialized_256_prepared,
            128 => &self.insert_batch_serialized_128_prepared,
            64 => &self.insert_batch_serialized_64_prepared,
            32 => &self.insert_batch_serialized_32_prepared,
            _ => unreachable!(),
        };

        // Process batches concurrently
        let chunks = values.chunks(*batch_size);
        stream::iter(chunks)
            .map(anyhow::Ok)
            .try_for_each_concurrent(CONCURRENCY_LIMIT, |chunk| {
                let batch_prepared = batch_prepared.clone();
                let session = session.clone();
                async move {
                    if chunk.len() == *batch_size {
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
        */
    }
    pub async fn set_double_id_merkle_nodes_batch_g_internal_fast_v5_grok_2<Hash: QHash256Base>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        if data.len() % QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE != 0 {
            anyhow::bail!("Data length is not a multiple of double id node size");
        }
        let num_nodes = data.len() / QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;

        if num_nodes == 0 {
            return Ok(());
        }

        const BATCH_SIZE: usize = 64; // Optimal based on benchmarks
        const CONCURRENCY_LIMIT: usize = 32; // Conservative limit to avoid overwhelming cluster

        // Parallel deserialization using Rayon
        let values: Vec<(i64, i64, i8, i64, i64, [u8; 32])> = (0..num_nodes)
            .into_par_iter()
            .map(|i| {
                let start = i * QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
                let end = start + QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
                let slice = &data[start..end];
                QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64)
            })
            .collect();

        // Create stream of batches
        let futures_iter = values.chunks(BATCH_SIZE).map(|chunk| {
            let mut batch = Batch::new(BatchType::Unlogged); // Use unlogged batch
            for _ in 0..chunk.len() {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values = chunk.to_vec();
            async move { session.batch(&batch, values).await.context("Batch insert failed") }
        });

        // Execute batches with controlled concurrency
        let mut stream = stream::iter(futures_iter).buffer_unordered(CONCURRENCY_LIMIT);
        while let Some(res) = stream.next().await {
            res?;
        }

        Ok(())
    }
    pub async fn set_double_id_merkle_nodes_batch_g_internal_fast_v5_gemini_1<Hash: QHash256Base>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        if data.len() % QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE != 0 {
            anyhow::bail!("Data length is not a multiple of double id node size");
        }
        let num_nodes = data.len() / QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;

        if num_nodes == 0 {
            return Ok(());
        }

        // --- The Alternative Approach ---

        // 1. Define a concurrency limit. This is the number of batches that can be
        //    "in-flight" to the database at any given time. This value is crucial for
        //    tuning. A good starting point is often between 50 and 200, depending on
        //    your hardware and network.
        const CONCURRENCY_LIMIT: usize = 128;
        const BATCH_SIZE: usize = 256;

        // 2. Create an iterator of work items. Instead of collecting futures into a
        //    Vec, we create an iterator that yields the data required for each batch.
        //    Each item is a slice of the original data corresponding to one batch.
        let chunks = data.chunks(QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE * BATCH_SIZE);

        // 3. Use `try_for_each_concurrent` to process the stream of chunks. This will
        //    maintain up to `CONCURRENCY_LIMIT` concurrent operations. When one async
        //    block finishes, a new one is started on the next chunk, ensuring a
        //    constant, controlled flow of requests.
        stream::iter(chunks)
            .map(anyhow::Ok) // Convert to a TryStream
            .try_for_each_concurrent(CONCURRENCY_LIMIT, |data_chunk| {
                // By moving `self` and `session` in the closure, we avoid lifetime issues.
                // The `async move` block is executed for each chunk.
                let this = self.clone();
                async move {
                    let num_nodes_in_chunk = data_chunk.len() / QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE;
                    if num_nodes_in_chunk == 0 {
                        return Ok(());
                    }

                    // Deserialize only the nodes for this specific chunk. This is more memory
                    // efficient than deserializing everything up front.
                    let values: Vec<(i64, i64, i8, i64, i64, [u8; 32])> = data_chunk
                        .chunks_exact(QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE)
                        .map(|slice| {
                            QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64)
                        })
                        .collect();

                    // Use the pre-prepared batch for full chunks, or build one for the last partial
                    // chunk.
                    if num_nodes_in_chunk == BATCH_SIZE {
                        session
                            .batch(&this.insert_batch_serialized_256_prepared, values)
                            .await
                            .context("Full batch insert failed")?;
                    } else {
                        let mut batch = Batch::default();
                        for _ in 0..num_nodes_in_chunk {
                            batch.append_statement(this.insert_1_statement.clone());
                        }
                        session.batch(&batch, values).await.context("Partial batch insert failed")?;
                    }
                    Ok(())
                }
            })
            .await?;

        Ok(())
    }

    // ... inside the impl block
    pub async fn set_double_id_merkle_nodes_batch_fast_v7_g<Hash: QHash256Base>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        if data.len() % QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE != 0 {
            anyhow::bail!("Data length is not a multiple of double id node size");
        }

        const BATCH_SIZE: usize = 256;

        // --- STEP 1: PARALLEL CPU-BOUND WORK ---
        // Use Rayon's `par_chunks` to process the raw data in parallel across all
        // available CPU cores. This deserializes everything up-front, but does
        // so extremely quickly. The result is a Vec of Vecs, where each inner
        // Vec is one batch's worth of values.
        let all_batches: Vec<Vec<_>> = data
            .par_chunks(QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE * BATCH_SIZE)
            .map(|data_chunk| {
                data_chunk
                    .chunks_exact(QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE)
                    .map(|slice| QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_signed_insert_tuple::<Hash>(slice, checkpoint_i64))
                    .collect() // Collect into the inner Vec for this batch
            })
            .collect(); // Collect all the batch Vecs into the outer Vec

        // --- STEP 2: CONCURRENT I/O-BOUND WORK ---
        // Now that all data is prepared, stream it to the database with bounded
        // concurrency.
        const CONCURRENCY_LIMIT: usize = 128;

        stream::iter(all_batches)
            .map(Ok)
            .try_for_each_concurrent(CONCURRENCY_LIMIT, |values| {
                let this = self.clone();
                async move {
                    let num_nodes_in_chunk = values.len();
                    if num_nodes_in_chunk == 0 {
                        return anyhow::Ok(());
                    }

                    if num_nodes_in_chunk == BATCH_SIZE {
                        session
                            .batch(&this.insert_batch_serialized_256_prepared, values)
                            .await
                            .context("Full batch insert failed")?;
                    } else {
                        let mut batch = Batch::default();
                        for _ in 0..num_nodes_in_chunk {
                            batch.append_statement(this.insert_1_statement.clone());
                        }
                        session.batch(&batch, values).await.context("Partial batch insert failed")?;
                    }
                    Ok(())
                }
            })
            .await?;

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::calc_best_batch_size;
    #[test]
    fn get_best_batch_size() {
        assert_eq!(calc_best_batch_size(64*1000, &[256, 128, 64]), 256);
        assert_eq!(calc_best_batch_size(100000, &[256, 128, 64]), 256);
        assert_eq!(calc_best_batch_size(10000, &[256, 128, 64]), 256);
        assert_eq!(calc_best_batch_size(1000, &[256, 128, 64]), 256);
        assert_eq!(calc_best_batch_size(512, &[256, 128, 64]), 256);
        assert_eq!(calc_best_batch_size(300, &[256, 128, 64]), 256);
        assert_eq!(calc_best_batch_size(200, &[256, 128, 64]), 128);
        assert_eq!(calc_best_batch_size(129, &[256, 128, 64]), 128);
        assert_eq!(calc_best_batch_size(128, &[256, 128, 64]), 128);
        assert_eq!(calc_best_batch_size(127, &[256, 128, 64]), 64);
        assert_eq!(calc_best_batch_size(65, &[256, 128, 64]), 64);
        assert_eq!(calc_best_batch_size(64, &[256, 128, 64]), 64);
        assert_eq!(calc_best_batch_size(63, &[256, 128, 64]), 32);
        assert_eq!(calc_best_batch_size(33, &[256, 128, 64]), 32);
        assert_eq!(calc_best_batch_size(32, &[256, 128, 64]), 32);
        assert_eq!(calc_best_batch_size(31, &[256, 128, 64]), 32);
        assert_eq!(calc_best_batch_size(1, &[256, 128, 64]), 32);
    }
}