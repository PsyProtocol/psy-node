/*use async_trait::async_trait;
use anyhow::Context;
use futures::future::join_all;
use psy_node_core::store::traits::core_db::{CoreDatabaseDoubleIdCheckpointedReader, CoreDatabaseDoubleIdCheckpointedWriter, CoreDatabaseKivReader, CoreDatabaseKivWriter, CoreDatabaseSingleIdCheckpointedReader, CoreDatabaseSingleIdCheckpointedWriter};
use scylla::statement::batch::Batch;
use crate::store::scylla::{constants::{INSERT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE, INSERT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE, INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE, SELECT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE, SELECT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE, SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE}, core::ScyllaCoreStore, tables::{merkle::{ScyllaDoubleMerkleNodesPreparedStatements, ScyllaMerkleNodesPreparedStatements}, object::{ScyllaGenericKeyIdValueTablePreparedStatements, ScyllaGenericObjectDoubleIdTablePreparedStatements, ScyllaGenericObjectSingleIdTablePreparedStatements}}, utils::{convert_checkpoint_id_to_i64, convert_i64_to_checkpoint_id, i64_to_u64_exact, u64_to_i64_exact}};
use postcard::{from_bytes, to_stdvec};
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::{db::row::{QDatabaseDoubleIdTableRow, QDatabaseDoubleIdTableRowCreatable, QDatabaseDoubleIdTableRowLike, QDatabaseDoubleIdTableRowNoCheckpointId, QDatabaseDoubleIdTableRowNoCheckpointIdLike, QDatabaseKeyIdValueTableRow, QDatabaseKeyIdValueTableRowCreatable, QDatabaseKeyIdValueTableRowLike, QDatabaseSingleIdTableRow, QDatabaseSingleIdTableRowCreatable, QDatabaseSingleIdTableRowLike, QDatabaseSingleIdTableRowNoCheckpointId, QDatabaseSingleIdTableRowNoCheckpointIdLike, QDoubleIdKey}, hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}}, protocol::core_types::QHashBase};
use serde::{de::DeserializeOwned, Serialize};

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseSingleIdCheckpointedReader<ScyllaGenericObjectSingleIdTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_select_one_single_checkpointed_object_value<V: DeserializeOwned + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, obj_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<V>> {
        let res = self.session.execute_unpaged(&table.select_value_1_prepared, (u64_to_i64_exact(obj_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => match from_bytes::<V>(&row.0) {
                Ok(value) => Ok(Some(value)),
                Err(e) => {
                    tracing::error!("Deserialization error for latest object ID with {} in table {}.{}: {:?}", obj_id, table.keyspace, table.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    async fn db_select_one_single_checkpointed_object_value_and_ids<V: DeserializeOwned + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, obj_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<QDatabaseSingleIdTableRow<V>>> {
        let res = self.session.execute_unpaged(&table.select_value_checkpoint_id_obj_id_1_prepared, (u64_to_i64_exact(obj_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, i64, Vec<u8>)>()? {
            Some(row) => match from_bytes::<V>(&row.2) {
                Ok(value) => Ok(Some(QDatabaseSingleIdTableRow {
                    value,
                    obj_id: i64_to_u64_exact(row.0),
                    checkpoint_id: convert_i64_to_checkpoint_id(row.1),
                })),
                Err(e) => {
                    tracing::error!("Deserialization error for object ID {} at checkpoint_id={} in {}.{}: {:?}", obj_id, convert_i64_to_checkpoint_id(row.1), table.keyspace, table.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    async fn db_select_one_single_checkpointed_object_value_and_ids_t<V: DeserializeOwned + Send + Sync, R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, obj_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<R>> {
        let res = self.session.execute_unpaged(&table.select_value_checkpoint_id_obj_id_1_prepared, (u64_to_i64_exact(obj_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, i64, Vec<u8>)>()? {
            Some(row) => match from_bytes::<V>(&row.2) {
                Ok(value) => Ok(Some(R::create_from_single_row(i64_to_u64_exact(row.0), convert_i64_to_checkpoint_id(row.1), value))),
                Err(e) => {
                    tracing::error!("Deserialization error for object ID {} at checkpoint_id={} in {}.{}: {:?}", obj_id, convert_i64_to_checkpoint_id(row.1), table.keyspace, table.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    async fn db_select_all_single_checkpointed_object<V: DeserializeOwned + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements) -> anyhow::Result<Vec<QDatabaseSingleIdTableRow<V>>> {
        let res = self.session.execute_unpaged(&table.select_all_prepared, ()).await?;
        let rows_result = res.into_rows_result()?;
        let rows_iter = rows_result.rows::<(i64,i64,Vec<u8>)>()?;
        let rows_vec: Vec<_> = rows_iter.collect();
        let mut results = Vec::with_capacity(rows_vec.len());
        for row in rows_vec {
            let (obj_id, checkpoint_id, value): (i64, i64, Vec<u8>) = row?;
            results.push(QDatabaseSingleIdTableRow {
                obj_id: i64_to_u64_exact(obj_id),
                checkpoint_id: convert_i64_to_checkpoint_id(checkpoint_id),
                value: match from_bytes(&value){
                    Ok(value) => value,
                    Err(e) => {
                        tracing::error!("Deserialization error for object ID {} at checkpoint_id={} in {}.{}: {:?}", obj_id, convert_i64_to_checkpoint_id(checkpoint_id), table.keyspace, table.table_name, e);
                        anyhow::bail!("Deserialization error for object ID {} at checkpoint_id={} in {}.{}: {:?}", obj_id, convert_i64_to_checkpoint_id(checkpoint_id), table.keyspace, table.table_name, e);
                    }
                },
            });
        }
        Ok(results)
    }

    async fn db_select_many_single_checkpointed_object_values<V: DeserializeOwned + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, obj_ids: &[u64], max_checkpoint_id: u64) -> anyhow::Result<Vec<Option<V>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
        let obj_ids_i64 = obj_ids.iter().map(|id| u64_to_i64_exact(*id)).collect::<Vec<_>>();
        for chunk in obj_ids_i64.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = self.session.clone();
                    let prep = table.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key, max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                            match from_bytes::<V>(&row.0) {
                                Ok(value) => core::result::Result::<_, anyhow::Error>::Ok(Some(value)),
                                Err(e) => {
                                    tracing::error!("Deserialization error for object ID {} with max_checkpoint_id={} in {}.{}: {:?}", i64_to_u64_exact(*key), max_checkpoint_id, table.keyspace, table.table_name, e);
                                    Ok(None)
                                }
                            }
                        } else {
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

    async fn db_select_many_single_checkpointed_object_keys_and_values<V: DeserializeOwned + Send + Sync, R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, obj_ids: &[u64], max_checkpoint_id: u64) -> anyhow::Result<Vec<R>> {
        
        let mut results = Vec::with_capacity(obj_ids.len());
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
        let obj_ids_i64 = obj_ids.iter().map(|id| u64_to_i64_exact(*id)).collect::<Vec<_>>();
        for chunk in obj_ids_i64.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = self.session.clone();
                    let prep = table.select_value_checkpoint_id_obj_id_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key, max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(i64, i64, Vec<u8>)>()? {
                            match pser::deserialize::<V>(&row.2) {
                                Ok(value) => core::result::Result::<_, anyhow::Error>::Ok(Some(R::create_from_single_row(i64_to_u64_exact(row.0), convert_i64_to_checkpoint_id(row.1), value))),
                                Err(e) => {
                                    tracing::error!("Deserialization error for object ID {} at checkpoint_id={} in {}.{}: {:?}", i64_to_u64_exact(*key), convert_i64_to_checkpoint_id(row.1), table.keyspace, table.table_name, e);
                                    Ok(None)
                                }
                            }
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

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseSingleIdCheckpointedWriter<ScyllaGenericObjectSingleIdTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_insert_one_single_checkpointed_object<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, obj_id: u64, checkpoint_id: u64, value: &V) -> anyhow::Result<()> {
        let value_bytes = to_stdvec(value)?;
        self.session.execute_unpaged(&table.insert_1_prepared, (u64_to_i64_exact(obj_id), u64_to_i64_exact(checkpoint_id), &value_bytes)).await?;
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_object_rows<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, rows: &[QDatabaseSingleIdTableRow<V>]) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _ in chunk {
                batch.append_statement(table.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| Ok((u64_to_i64_exact(n.obj_id), convert_checkpoint_id_to_i64(n.checkpoint_id), to_stdvec(&n.value)?)))
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| self.session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_object_rows_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseSingleIdTableRowLike<V> + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, rows: &[R]) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _ in chunk {
                batch.append_statement(table.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| Ok((u64_to_i64_exact(n.get_row_obj_id()), convert_checkpoint_id_to_i64(n.get_row_checkpoint_id()), to_stdvec(n.get_row_value_ref())?)))
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| self.session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_objects_at_checkpoint<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, checkpoint_id: u64, rows: &[QDatabaseSingleIdTableRowNoCheckpointId<V>]) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _ in chunk {
                batch.append_statement(table.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| Ok((u64_to_i64_exact(n.obj_id), convert_checkpoint_id_to_i64(checkpoint_id), to_stdvec(&n.value)?)))
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| self.session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseSingleIdTableRowNoCheckpointIdLike<V> + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, checkpoint_id: u64, rows: &[R]) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _ in chunk {
                batch.append_statement(table.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| Ok((u64_to_i64_exact(n.get_row_obj_id()), convert_checkpoint_id_to_i64(checkpoint_id), to_stdvec(n.get_row_value_ref())?)))
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| self.session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseDoubleIdCheckpointedReader<ScyllaGenericObjectDoubleIdTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_select_one_double_checkpointed_object_value<V: DeserializeOwned + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, obj_id: u64, secondary_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<V>> {
        let res = self.session.execute_unpaged(&table.select_value_1_prepared, (u64_to_i64_exact(obj_id), u64_to_i64_exact(secondary_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => match from_bytes::<V>(&row.0) {
                Ok(value) => Ok(Some(value)),
                Err(e) => {
                    tracing::error!("Deserialization error for latest object ID with ({}, {}) in table {}.{}: {:?}", obj_id, secondary_id, table.keyspace, table.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    async fn db_select_one_double_checkpointed_object_value_and_ids<V: DeserializeOwned + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, obj_id: u64, secondary_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<QDatabaseDoubleIdTableRow<V>>> {
        let res = self.session.execute_unpaged(&table.select_value_checkpoint_id_obj_ids_1_prepared, (u64_to_i64_exact(obj_id), u64_to_i64_exact(secondary_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, i64, i64, Vec<u8>)>()? {
            Some(row) => match from_bytes::<V>(&row.3) {
                Ok(value) => Ok(Some(QDatabaseDoubleIdTableRow {
                    value,
                    obj_id: i64_to_u64_exact(row.0),
                    secondary_id: i64_to_u64_exact(row.1),
                    checkpoint_id: convert_i64_to_checkpoint_id(row.2),
                })),
                Err(e) => {
                    tracing::error!("Deserialization error for object ID ({}, {}) at checkpoint_id={} in {}.{}: {:?}", obj_id, secondary_id, convert_i64_to_checkpoint_id(row.2), table.keyspace, table.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    async fn db_select_one_double_checkpointed_object_value_and_ids_t<V: DeserializeOwned + Send + Sync, R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, obj_id: u64, secondary_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<R>> {
        let res = self.session.execute_unpaged(&table.select_value_checkpoint_id_obj_ids_1_prepared, (u64_to_i64_exact(obj_id), u64_to_i64_exact(secondary_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, i64, i64, Vec<u8>)>()? {
            Some(row) => match from_bytes::<V>(&row.3) {
                Ok(value) => Ok(Some(R::create_from_double_row(i64_to_u64_exact(row.0), i64_to_u64_exact(row.1), convert_i64_to_checkpoint_id(row.2), value))),
                Err(e) => {
                    tracing::error!("Deserialization error for object ID ({}, {}) at checkpoint_id={} in {}.{}: {:?}", obj_id, secondary_id, convert_i64_to_checkpoint_id(row.2), table.keyspace, table.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    async fn db_select_all_double_checkpointed_object<V: DeserializeOwned + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements) -> anyhow::Result<Vec<QDatabaseDoubleIdTableRow<V>>> {
        let res = self.session.execute_unpaged(&table.select_all_prepared, ()).await?;
        let rows_result = res.into_rows_result()?;
        let rows_iter = rows_result.rows::<(i64,i64,i64,Vec<u8>)>()?;
        let rows_vec: Vec<_> = rows_iter.collect();
        let mut results = Vec::with_capacity(rows_vec.len());
        for row in rows_vec {
            let (obj_id, secondary_id, checkpoint_id, value): (i64, i64, i64, Vec<u8>) = row?;
            results.push(QDatabaseDoubleIdTableRow {
                obj_id: i64_to_u64_exact(obj_id),
                secondary_id: i64_to_u64_exact(secondary_id),
                checkpoint_id: convert_i64_to_checkpoint_id(checkpoint_id),
                value: match from_bytes(&value){
                    Ok(value) => value,
                    Err(e) => {
                        tracing::error!("Deserialization error for object ID ({}, {}) at checkpoint_id={} in {}.{}: {:?}", obj_id, secondary_id, convert_i64_to_checkpoint_id(checkpoint_id), table.keyspace, table.table_name, e);
                        anyhow::bail!("Deserialization error for object ID ({}, {}) at checkpoint_id={} in {}.{}: {:?}", obj_id, secondary_id, convert_i64_to_checkpoint_id(checkpoint_id), table.keyspace, table.table_name, e);
                    }
                },
            });
        }
        Ok(results)
    }

    async fn db_select_many_double_checkpointed_object_values<V: DeserializeOwned + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, obj_ids: &[QDoubleIdKey], max_checkpoint_id: u64) -> anyhow::Result<Vec<Option<V>>> {
        
        let mut results = Vec::with_capacity(obj_ids.len());
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
        for chunk in obj_ids.chunks(SELECT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = self.session.clone();
                    let prep = table.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (u64_to_i64_exact(key.obj_id), u64_to_i64_exact(key.secondary_id), max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                            match pser::deserialize::<V>(&row.0) {
                                Ok(value) => core::result::Result::<_, anyhow::Error>::Ok(Some(value)),
                                Err(e) => {
                                    tracing::error!("Deserialization error for object ID ({},{}) with max_checkpoint_id={} in {}.{}: {:?}", key.obj_id, key.secondary_id, convert_i64_to_checkpoint_id(max_cp_i64), table.keyspace, table.table_name, e);
                                    Ok(None)
                                }
                            }
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

    async fn db_select_many_double_checkpointed_object_keys_and_values<V: DeserializeOwned + Send + Sync, R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, obj_ids: &[QDoubleIdKey], max_checkpoint_id: u64) -> anyhow::Result<Vec<R>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
        for chunk in obj_ids.chunks(SELECT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = self.session.clone();
                    let prep = table.select_value_checkpoint_id_obj_ids_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (u64_to_i64_exact(key.obj_id), u64_to_i64_exact(key.secondary_id), max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(i64, i64, i64, Vec<u8>)>()? {
                            match pser::deserialize::<V>(&row.3) {
                                Ok(value) => core::result::Result::<_, anyhow::Error>::Ok(Some(R::create_from_double_row(i64_to_u64_exact(row.0), i64_to_u64_exact(row.1), convert_i64_to_checkpoint_id(row.2), value))),
                                Err(e) => {
                                    tracing::error!("Deserialization error for object ID ({},{}) at checkpoint_id={} in {}.{}: {:?}", key.obj_id, key.secondary_id, convert_i64_to_checkpoint_id(row.2), table.keyspace, table.table_name, e);
                                    Ok(None)
                                }
                            }
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

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseDoubleIdCheckpointedWriter<ScyllaGenericObjectDoubleIdTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_insert_one_double_checkpointed_object<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, obj_id: u64, secondary_id: u64, checkpoint_id: u64, value: &V) -> anyhow::Result<()> {
        let value_bytes = to_stdvec(value)?;
        self.session.execute_unpaged(&table.insert_1_prepared, (u64_to_i64_exact(obj_id), u64_to_i64_exact(secondary_id), u64_to_i64_exact(checkpoint_id), &value_bytes)).await?;
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_object_rows<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, rows: &[QDatabaseDoubleIdTableRow<V>]) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _ in chunk {
                batch.append_statement(table.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| Ok((u64_to_i64_exact(n.obj_id), u64_to_i64_exact(n.secondary_id), convert_checkpoint_id_to_i64(n.checkpoint_id), to_stdvec(&n.value)?)))
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| self.session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_object_rows_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseDoubleIdTableRowLike<V> + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, rows: &[R]) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _ in chunk {
                batch.append_statement(table.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| Ok((u64_to_i64_exact(n.get_row_obj_id()), u64_to_i64_exact(n.get_row_secondary_id()), convert_checkpoint_id_to_i64(n.get_row_checkpoint_id()), to_stdvec(n.get_row_value_ref())?)))
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| self.session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_objects_at_checkpoint<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, checkpoint_id: u64, rows: &[QDatabaseDoubleIdTableRowNoCheckpointId<V>]) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _ in chunk {
                batch.append_statement(table.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| Ok((u64_to_i64_exact(n.obj_id), u64_to_i64_exact(n.secondary_id), convert_checkpoint_id_to_i64(checkpoint_id), to_stdvec(&n.value)?)))
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| self.session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_objects_at_checkpoint_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseDoubleIdTableRowNoCheckpointIdLike<V> + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, checkpoint_id: u64, rows: &[R]) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _ in chunk {
                batch.append_statement(table.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| Ok((u64_to_i64_exact(n.get_row_obj_id()), u64_to_i64_exact(n.get_row_secondary_id()), convert_checkpoint_id_to_i64(checkpoint_id), to_stdvec(n.get_row_value_ref())?)))
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| self.session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseKivReader<ScyllaGenericKeyIdValueTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_select_one_kiv_value<V: DeserializeOwned + Send + Sync>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, obj_id: u64) -> anyhow::Result<Option<V>> {
        let res = self.session.execute_unpaged(&table.select_value_1_prepared, (u64_to_i64_exact(obj_id),)).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => match from_bytes::<V>(&row.0) {
                Ok(value) => Ok(Some(value)),
                Err(e) => {
                    tracing::error!("Deserialization error for latest object ID with {} in table {}.{}: {:?}", obj_id, table.keyspace, table.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    async fn db_select_one_kiv_value_and_ids<V: DeserializeOwned + Send + Sync>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, obj_id: u64) -> anyhow::Result<Option<QDatabaseKeyIdValueTableRow<V>>> {
        let res = self.session.execute_unpaged(&table.select_value_obj_id_1_prepared, (u64_to_i64_exact(obj_id),)).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, Vec<u8>)>()? {
            Some(row) => match from_bytes::<V>(&row.1) {
                Ok(value) => Ok(Some(QDatabaseKeyIdValueTableRow {
                    value,
                    obj_id: i64_to_u64_exact(row.0),
                })),
                Err(e) => {
                    tracing::error!("Deserialization error for object ID {} in {}.{}: {:?}", obj_id, table.keyspace, table.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    async fn db_select_one_kiv_value_and_ids_t<V: DeserializeOwned + Send + Sync, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, obj_id: u64) -> anyhow::Result<Option<R>> {
        let res = self.session.execute_unpaged(&table.select_value_obj_id_1_prepared, (u64_to_i64_exact(obj_id),)).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, Vec<u8>)>()? {
            Some(row) => match from_bytes::<V>(&row.1) {
                Ok(value) => Ok(Some(R::create_from_key_id_value_row(i64_to_u64_exact(row.0), value))),
                Err(e) => {
                    tracing::error!("Deserialization error for object ID {} in {}.{}: {:?}", obj_id, table.keyspace, table.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    async fn db_select_all_kiv<V: DeserializeOwned + Send + Sync>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements) -> anyhow::Result<Vec<QDatabaseKeyIdValueTableRow<V>>> {
        let res = self.session.execute_unpaged(&table.select_all_prepared, ()).await?;
        let rows_result = res.into_rows_result()?;
        let rows_iter = rows_result.rows::<(i64,Vec<u8>)>()?;
        let rows_vec: Vec<_> = rows_iter.collect();
        let mut results = Vec::with_capacity(rows_vec.len());
        for row in rows_vec {
            let (obj_id, value): (i64, Vec<u8>) = row?;
            results.push(QDatabaseKeyIdValueTableRow {
                obj_id: i64_to_u64_exact(obj_id),
                value: match from_bytes(&value){
                    Ok(value) => value,
                    Err(e) => {
                        tracing::error!("Deserialization error for object ID {} in {}.{}: {:?}", obj_id, table.keyspace, table.table_name, e);
                        anyhow::bail!("Deserialization error for object ID {} in {}.{}: {:?}", obj_id, table.keyspace, table.table_name, e);
                    }
                },
            });
        }
        Ok(results)
    }

    async fn db_select_many_kiv_values<V: DeserializeOwned + Send + Sync>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, obj_ids: &[u64]) -> anyhow::Result<Vec<Option<V>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let obj_ids_i64 = obj_ids.iter().map(|id| u64_to_i64_exact(*id)).collect::<Vec<_>>();
        for chunk in obj_ids_i64.chunks(SELECT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = self.session.clone();
                    let prep = table.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key,)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                            match from_bytes::<V>(&row.0) {
                                Ok(value) => Ok(Some(value)),
                                Err(e) => {
                                    tracing::error!("Deserialization error for object ID {} in {}.{}: {:?}", i64_to_u64_exact(*key), table.keyspace, table.table_name, e);
                                    Ok(None)
                                }
                            }
                        } else {
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

    async fn db_select_many_kiv_keys_and_values<V: DeserializeOwned + Send + Sync, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, obj_ids: &[u64]) -> anyhow::Result<Vec<R>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let obj_ids_i64 = obj_ids.iter().map(|id| u64_to_i64_exact(*id)).collect::<Vec<_>>();
        for chunk in obj_ids_i64.chunks(SELECT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = self.session.clone();
                    let prep = table.select_value_obj_id_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key,)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(i64, Vec<u8>)>()? {
                            match from_bytes::<V>(&row.1) {
                                Ok(value) => Ok(Some(R::create_from_key_id_value_row(i64_to_u64_exact(row.0), value))),
                                Err(e) => {
                                    tracing::error!("Deserialization error for object ID {} in {}.{}: {:?}", i64_to_u64_exact(*key), table.keyspace, table.table_name, e);
                                    Ok(None)
                                }
                            }
                        } else {
                            Ok(None)
                        }
                    }
                })
                .collect();
            let chunk_results = join_all(futures).await;
            for res in chunk_results {
                if let Some(r) = res? {
                    results.push(r);
                }
            }
        }
        Ok(results)
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseKivWriter<ScyllaGenericKeyIdValueTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_insert_one_kiv<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, obj_id: u64, value: &V) -> anyhow::Result<()> {
        let value_bytes = to_stdvec(value)?;
        self.session.execute_unpaged(&table.insert_1_prepared, (u64_to_i64_exact(obj_id), &value_bytes)).await?;
        Ok(())
    }

    async fn db_insert_many_kivs<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, rows: &[QDatabaseKeyIdValueTableRow<V>]) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _ in chunk {
                batch.append_statement(table.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| Ok((u64_to_i64_exact(n.obj_id), to_stdvec(&n.value)?)))
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| self.session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }

    async fn db_insert_many_kivs_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseKeyIdValueTableRowLike<V> + Send + Sync>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, rows: &[R]) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _ in chunk {
                batch.append_statement(table.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| Ok((u64_to_i64_exact(n.get_row_obj_id()), to_stdvec(n.get_row_value_ref())?)))
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| self.session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }
}

*/