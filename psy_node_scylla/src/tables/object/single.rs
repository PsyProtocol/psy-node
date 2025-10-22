use futures::{future::join_all, stream, StreamExt, TryStreamExt};

use psy_serialize::PsySerializeCanonicalAsyncSafe;
use rayon::slice::{ParallelSlice};
use rayon::iter::ParallelIterator;
use std::sync::Arc;
use anyhow::Context;
use async_trait::async_trait;
use parth_core::data::db::{row::{QDatabaseSingleIdTableRow, QDatabaseSingleIdTableRowCreatable, QDatabaseSingleIdTableRowLike, QDatabaseSingleIdTableRowNoCheckpointId, QDatabaseSingleIdTableRowNoCheckpointIdLike}, table::QDatabaseTableRoutingKey};
use scylla::{client::session::Session, statement::{batch::Batch, prepared::PreparedStatement, Statement}};

use crate::utils::calc_best_batch_size;
use crate::{constants::{INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE, SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE}, tables::traits::ScyllaStandardPreparedTableStatements, utils::{convert_checkpoint_id_to_i64, convert_i64_to_checkpoint_id, generate_batch_prepared_statement, i64_to_u64_exact, u64_to_i64_exact}};






#[derive(Clone)]
pub struct ScyllaGenericObjectSingleIdTablePreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,
    
    pub select_value_1_statement: Statement,
    pub select_value_1_prepared: Arc<PreparedStatement>,

    pub select_value_checkpoint_id_obj_id_1_statement: Statement,
    pub select_value_checkpoint_id_obj_id_1_prepared: Arc<PreparedStatement>,

    
    pub insert_batch_serialized_256_prepared: Arc<Batch>,
    pub insert_batch_serialized_128_prepared: Arc<Batch>,
    pub insert_batch_serialized_64_prepared: Arc<Batch>,

    pub select_all_statement: Statement,
    pub select_all_prepared: Arc<PreparedStatement>,

    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
}

impl ScyllaGenericObjectSingleIdTablePreparedStatements {
    pub async fn new_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(format!("INSERT INTO {}.{} (obj_id, checkpoint_id, value) VALUES (?, ?, ?)", keyspace, table_name));
        let insert_1_prepared = session.prepare(insert_1_statement.clone()).await?;
        
        let select_value_1_statement = Statement::new(format!("SELECT value FROM {}.{} WHERE obj_id = ? AND checkpoint_id <= ? LIMIT 1", keyspace, table_name));
        let select_value_1_prepared = session.prepare(select_value_1_statement.clone()).await?;
        
        let select_value_checkpoint_id_obj_id_1_statement = Statement::new(format!("SELECT obj_id, checkpoint_id, value FROM {}.{} WHERE obj_id = ? AND checkpoint_id <= ? LIMIT 1", keyspace, table_name));
        let select_value_checkpoint_id_obj_id_1_prepared = session.prepare(select_value_checkpoint_id_obj_id_1_statement.clone()).await?;

        let select_all_statement = Statement::new(format!("SELECT obj_id, checkpoint_id, value FROM {}.{}", keyspace, table_name));
        let select_all_prepared = session.prepare(select_all_statement.clone()).await?;

        Ok(Self {

            insert_batch_serialized_256_prepared: Arc::new(generate_batch_prepared_statement(&session, &insert_1_prepared, 512).await?),
            insert_batch_serialized_128_prepared: Arc::new(generate_batch_prepared_statement(&session, &insert_1_prepared, 128).await?),
            insert_batch_serialized_64_prepared: Arc::new(generate_batch_prepared_statement(&session, &insert_1_prepared, 64).await?),  
            insert_1_statement: insert_1_statement,
            insert_1_prepared: Arc::new(insert_1_prepared),
            select_value_1_statement: select_value_1_statement,
            select_value_1_prepared: Arc::new(select_value_1_prepared),
            select_value_checkpoint_id_obj_id_1_statement: select_value_checkpoint_id_obj_id_1_statement,
            select_value_checkpoint_id_obj_id_1_prepared: Arc::new(select_value_checkpoint_id_obj_id_1_prepared),
            select_all_statement: select_all_statement,
            select_all_prepared: Arc::new(select_all_prepared),
            keyspace: keyspace.to_string(),
            table_name: table_name.to_string(),
            table_key,
        })
    }
    pub async fn create_table(session: Arc<Session>, keyspace: &str, table_name: &str, _table_key: QDatabaseTableRoutingKey) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!("CREATE TABLE IF NOT EXISTS {}.{} (
                    obj_id BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((obj_id), checkpoint_id)
                ) WITH CLUSTERING ORDER BY (checkpoint_id DESC)", keyspace, table_name),
                &[],
            ).await?;
        session.await_schema_agreement().await?;
        Ok(())
    }
    pub async fn new_create_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        Self::create_table(session.clone(), keyspace, table_name, table_key).await?;
        Self::new_from_session(session, keyspace, table_name, table_key).await
    }
}



#[async_trait]
impl ScyllaStandardPreparedTableStatements for ScyllaGenericObjectSingleIdTablePreparedStatements {
    async fn create_table_standard(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        Self::new_create_from_session(session, keyspace, table_name, table_key).await
    }
}


impl ScyllaGenericObjectSingleIdTablePreparedStatements {
async fn insert_many_single_checkpointed_objects_at_checkpoint_ffs_clip_id_at_start_internal(
        &self,
        session: &Session, 
        object_size_without_id: usize,
        checkpoint_id: u64,
        data: &[u8],
        batch_size: usize,
    ) -> anyhow::Result<()>{
        let object_size_with_id = object_size_without_id + 8;

        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        if data.len() < object_size_with_id || data.len() % object_size_with_id != 0 {
            anyhow::bail!("Data length is not a multiple of object size with id");
        }
        let num_nodes = data.len() / object_size_with_id;

        if num_nodes == 0 {
            return Ok(());
        }

        const CONCURRENCY_LIMIT: usize = 64; // Tuned for typical Scylla clusters


        // Parallel deserialization using rayon
        let values: Vec<(i64, i64, &[u8])> = data
            .par_chunks(object_size_with_id)
            .map(|slice| {
                (
                    i64::from_le_bytes(slice[0..8].try_into().unwrap()),
                    checkpoint_i64,
                    &slice[8..object_size_with_id],
                )
            })
            .collect();

        // Map batch size to pre-prepared batch
        let batch_prepared = match batch_size {
            //512 => &self.insert_batch_serialized_512_prepared,
            256 => &self.insert_batch_serialized_256_prepared,
            128 => &self.insert_batch_serialized_128_prepared,
            64 => &self.insert_batch_serialized_64_prepared,
            //32 => &self.insert_batch_serialized_32_prepared,
            _ => anyhow::bail!("Unsupported batch size"),
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
    
    async fn insert_many_single_checkpointed_objects_at_checkpoint_ffs_with_id_at_index_internal(
        &self,
        session: &Session, 
        object_size: usize,
        object_id_location: usize,
        checkpoint_id: u64,
        data: &[u8],
        batch_size: usize,
    ) -> anyhow::Result<()>{
        if object_id_location + 8 > object_size {
            anyhow::bail!("Object ID location is out of bounds");
        }


        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        if data.len() < object_size || data.len() % object_size != 0 {
            anyhow::bail!("Data length is not a multiple of object size with id");
        }
        let num_nodes = data.len() / object_size;

        if num_nodes == 0 {
            return Ok(());
        }

        const CONCURRENCY_LIMIT: usize = 64; // Tuned for typical Scylla clusters


        // Parallel deserialization using rayon
        let values: Vec<(i64, i64, &[u8])> = data
            .par_chunks(object_size)
            .map(|slice| {
                (
                    i64::from_le_bytes(slice[object_id_location..object_id_location+8].try_into().unwrap()),
                    checkpoint_i64,
                    &slice[..],
                )
            })
            .collect();

        // Map batch size to pre-prepared batch
        let batch_prepared = match batch_size {
            //512 => &self.insert_batch_serialized_512_prepared,
            256 => &self.insert_batch_serialized_256_prepared,
            128 => &self.insert_batch_serialized_128_prepared,
            64 => &self.insert_batch_serialized_64_prepared,
            //32 => &self.insert_batch_serialized_32_prepared,
            _ => anyhow::bail!("Unsupported batch size {}", batch_size),
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
    // first 8 bytes are the object_id, last_8 bytes 
    pub async fn insert_many_single_checkpointed_objects_at_checkpoint_ffs_clip_id_at_start<'a>(
        &self,
        session: &Session, 
        object_size_without_id: usize,
        checkpoint_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()>{
        if data.len() % (object_size_without_id+8) != 0 {
            anyhow::bail!("Data length is not a multiple of object size with id");
        }
        let num_nodes = data.len() / (object_size_without_id + 8);
        if num_nodes == 0 {
            return Ok(());
        }
        
        let batch_size = calc_best_batch_size(num_nodes, &[256, 128, 64]);
        self.insert_many_single_checkpointed_objects_at_checkpoint_ffs_clip_id_at_start_internal(session, object_size_without_id, checkpoint_id, data, batch_size).await
        
    }

    // for user leafs and similar, where we want to insert many objects at a checkpoint, but the id is at the end of the row
    pub async fn insert_many_single_checkpointed_objects_at_checkpoint_ffs_with_id_at_index(
        &self,
        session: &Session, 
        object_size: usize,
        object_id_location: usize,
        checkpoint_id: u64,
        rows: &[u8],
    ) -> anyhow::Result<()>{
        if rows.len() % object_size != 0 {
            anyhow::bail!("Data length is not a multiple of object size with id");
        }
        let num_nodes = rows.len() / object_size;
        if num_nodes == 0 {
            return Ok(());
        }
        
        let batch_size = calc_best_batch_size(num_nodes, &[256, 128, 64]);
        self.insert_many_single_checkpointed_objects_at_checkpoint_ffs_with_id_at_index_internal(session, object_size, object_id_location, checkpoint_id, rows, batch_size).await


    }
    pub async fn select_one_single_checkpointed_object_value<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        obj_id: u64, 
        max_checkpoint_id: u64
    ) -> anyhow::Result<Option<V>> {
        let res = session.execute_unpaged(&self.select_value_1_prepared, (u64_to_i64_exact(obj_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => Ok(Some(V::psy_ser_from_owned_bytes_vec(row.0)?)),
            None => Ok(None), // Return zero hash if not found
        }
    }
    pub async fn select_one_single_checkpointed_object_value_and_ids<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        obj_id: u64, 
        max_checkpoint_id: u64
    ) -> anyhow::Result<Option<QDatabaseSingleIdTableRow<V>>> {
        let res = session.execute_unpaged(&self.select_value_checkpoint_id_obj_id_1_prepared, (u64_to_i64_exact(obj_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, i64, Vec<u8>)>()? {

            Some(row) => Ok(Some(QDatabaseSingleIdTableRow{
                obj_id: i64_to_u64_exact(row.0),
                checkpoint_id: convert_i64_to_checkpoint_id(row.1),
                value: V::psy_ser_from_owned_bytes_vec(row.2)?,
            })),
            None => Ok(None), // Return zero hash if not found
        }
    }
    pub async fn select_one_single_checkpointed_object_value_and_ids_t<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseSingleIdTableRowCreatable<V>>(
        &self, 
        session: &Session, 
        obj_id: u64, 
        max_checkpoint_id: u64
    ) -> anyhow::Result<Option<R>> {
        let res = session.execute_unpaged(&self.select_value_checkpoint_id_obj_id_1_prepared, (u64_to_i64_exact(obj_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, i64, Vec<u8>)>()? {
            Some(row) => {
                Ok(Some(R::create_from_single_row(i64_to_u64_exact(row.0), convert_i64_to_checkpoint_id(row.1), V::psy_ser_from_owned_bytes_vec(row.2)?)))
            },
            None => Ok(None), // Return zero hash if not found
        }
    }


    
    pub async fn select_all_single_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
    ) -> anyhow::Result<Vec<QDatabaseSingleIdTableRow<V>>> {
        let res = session.execute_unpaged(&self.select_all_prepared, ()).await?;
        let rows_result = res.into_rows_result()?;
        let rows_iter = rows_result.rows::<(i64,i64,Vec<u8>)>()?;
        let rows_vec: Vec<_> = rows_iter.collect();
        let mut results = Vec::with_capacity(rows_vec.len());

        for row in rows_vec {
            let (obj_id, checkpoint_id, value): (i64, i64, Vec<u8>) = row?;
            results.push(QDatabaseSingleIdTableRow {
                obj_id: i64_to_u64_exact(obj_id),
                checkpoint_id: convert_i64_to_checkpoint_id(checkpoint_id),
                value: V::psy_ser_from_owned_bytes_vec(value)?,
            });
        }
        Ok(results)
    }


    pub async fn insert_one_single_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        obj_id: u64, 
        checkpoint_id: u64, 
        value: &V
    ) -> anyhow::Result<()> {
        let value_bytes = value.psy_ser_to_bytes_vec()?;
        session.execute_unpaged(&self.insert_1_prepared, (u64_to_i64_exact(obj_id), u64_to_i64_exact(checkpoint_id), value_bytes)).await?;
        Ok(())
    }
    pub async fn insert_many_single_checkpointed_object_rows<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        rows: &[QDatabaseSingleIdTableRow<V>]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let mut value_list: Vec<Vec<(i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.obj_id), convert_checkpoint_id_to_i64(n.checkpoint_id), n.value.psy_ser_to_bytes_vec()?))
                })
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }

    pub async fn insert_many_single_checkpointed_object_rows_t<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseSingleIdTableRowLike<V>>(
        &self, 
        session: &Session, 
        rows: &[R]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let mut value_list: Vec<Vec<(i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.get_row_obj_id()), convert_checkpoint_id_to_i64(n.get_row_checkpoint_id()), n.get_row_value_ref().psy_ser_to_bytes_vec()?))
                })
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }
    pub async fn insert_many_single_checkpointed_objects_at_checkpoint<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        checkpoint_id: u64,
        rows: &[QDatabaseSingleIdTableRowNoCheckpointId<V>]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let mut value_list: Vec<Vec<(i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.obj_id), convert_checkpoint_id_to_i64(checkpoint_id), n.value.psy_ser_to_bytes_vec()?))
                })
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }
    pub async fn insert_many_single_checkpointed_objects_at_checkpoint_t<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseSingleIdTableRowNoCheckpointIdLike<V>>(
        &self, 
        session: &Session, 
        checkpoint_id: u64,
        rows: &[R]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let mut value_list: Vec<Vec<(i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.get_row_obj_id()), convert_checkpoint_id_to_i64(checkpoint_id), n.get_row_value_ref().psy_ser_to_bytes_vec()?))
                })
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }
    pub async fn select_many_single_checkpointed_object_values<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        obj_ids: &[u64], 
        max_checkpoint_id: u64
    ) -> anyhow::Result<Vec<Option<V>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
        let obj_ids_i64 = obj_ids.iter().map(|id| u64_to_i64_exact(*id)).collect::<Vec<_>>();
        for chunk in obj_ids_i64.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    
                    let prep = self.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key, max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                            anyhow::Ok(Some(V::psy_ser_from_owned_bytes_vec(row.0)?))
                        } else {
                            // Assume reverse_level = level for simplicity; adjust if tree height known
                            Ok(None)
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
    pub async fn select_many_single_checkpointed_object_keys_and_values<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseSingleIdTableRowCreatable<V>>(
        &self, 
        session: &Session, 
        obj_ids: &[u64], 
        max_checkpoint_id: u64
    ) -> anyhow::Result<Vec<R>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
        let obj_ids_i64 = obj_ids.iter().map(|id| u64_to_i64_exact(*id)).collect::<Vec<_>>();
        for chunk in obj_ids_i64.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    
                    let prep = self.select_value_checkpoint_id_obj_id_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key, max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(i64, i64, Vec<u8>)>()? {
                            anyhow::Ok(Some(R::create_from_single_row(i64_to_u64_exact(row.0), convert_i64_to_checkpoint_id(row.1), V::psy_ser_from_owned_bytes_vec(row.2)?)))
                        } else {
                            // Assume reverse_level = level for simplicity; adjust if tree height known
                            Ok(None)
                        }
                    }
                })
                .collect();
            let chunk_results = join_all(futures).await;
            for res in chunk_results {
                let r = res?;
                if let Some(r) = r {
                    results.push(r);
                }
            }
        }
        Ok(results)
    }

}