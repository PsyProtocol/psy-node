use std::sync::Arc;
use anyhow::Context;
use async_trait::async_trait;
use futures::future::join_all;
use parth_core::data::db::{row::{QDatabaseDoubleIdTableRow, QDatabaseDoubleIdTableRowCreatable, QDatabaseDoubleIdTableRowLike, QDatabaseDoubleIdTableRowNoCheckpointId, QDatabaseDoubleIdTableRowNoCheckpointIdLike, QDoubleIdKey}, table::QDatabaseTableRoutingKey};
use psy_serialize::PsySerializeCanonicalAsyncSafe;
use scylla::{client::session::Session, statement::{batch::Batch, prepared::PreparedStatement, Statement}};

use crate::{constants::{INSERT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE, SELECT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE}, tables::traits::ScyllaStandardPreparedTableStatements, utils::{convert_checkpoint_id_to_i64, convert_i64_to_checkpoint_id, i64_to_u64_exact, u64_to_i64_exact}};




#[derive(Clone)]
pub struct ScyllaGenericObjectDoubleIdTablePreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,
    
    pub select_value_1_statement: Statement,
    pub select_value_1_prepared: Arc<PreparedStatement>,

    pub select_value_checkpoint_id_obj_ids_1_statement: Statement,
    pub select_value_checkpoint_id_obj_ids_1_prepared: Arc<PreparedStatement>,

    pub select_all_statement: Statement,
    pub select_all_prepared: Arc<PreparedStatement>,

    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
}

impl ScyllaGenericObjectDoubleIdTablePreparedStatements {
    pub async fn new_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(format!("INSERT INTO {}.{} (obj_id, secondary_id, checkpoint_id, value) VALUES (?, ?, ?, ?)", keyspace, table_name));
        let insert_1_prepared = session.prepare(insert_1_statement.clone()).await?;
        
        let select_value_1_statement = Statement::new(format!("SELECT value FROM {}.{} WHERE obj_id = ? AND secondary_id = ? AND checkpoint_id <= ? LIMIT 1", keyspace, table_name));
        let select_value_1_prepared = session.prepare(select_value_1_statement.clone()).await?;

        let select_value_checkpoint_id_obj_ids_1_statement = Statement::new(format!("SELECT obj_id, secondary_id, checkpoint_id, value FROM {}.{} WHERE obj_id = ? AND secondary_id = ? AND checkpoint_id <= ? LIMIT 1", keyspace, table_name));
        let select_value_checkpoint_id_obj_ids_1_prepared = session.prepare(select_value_checkpoint_id_obj_ids_1_statement.clone()).await?;

        let select_all_statement = Statement::new(format!("SELECT obj_id, secondary_id, checkpoint_id, value FROM {}.{}", keyspace, table_name));
        let select_all_prepared = session.prepare(select_all_statement.clone()).await?;

        Ok(Self {
            insert_1_statement: insert_1_statement,
            insert_1_prepared: Arc::new(insert_1_prepared),
            select_value_1_statement: select_value_1_statement,
            select_value_1_prepared: Arc::new(select_value_1_prepared),
            select_value_checkpoint_id_obj_ids_1_statement: select_value_checkpoint_id_obj_ids_1_statement,
            select_value_checkpoint_id_obj_ids_1_prepared: Arc::new(select_value_checkpoint_id_obj_ids_1_prepared),
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
                    secondary_id BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((obj_id, secondary_id), checkpoint_id)
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
impl ScyllaStandardPreparedTableStatements for ScyllaGenericObjectDoubleIdTablePreparedStatements {
    async fn create_table_standard(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        Self::new_create_from_session(session, keyspace, table_name, table_key).await
    }
}



impl ScyllaGenericObjectDoubleIdTablePreparedStatements {

    pub async fn select_one_double_checkpointed_object_value<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64
    ) -> anyhow::Result<Option<V>> {
        let res = session.execute_unpaged(&self.select_value_1_prepared, (u64_to_i64_exact(obj_id), u64_to_i64_exact(secondary_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => Ok(Some(V::psy_ser_from_owned_bytes_vec(row.0)?)),
            None => Ok(None),
        }
    }
    pub async fn select_one_double_checkpointed_object_value_and_ids<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        obj_id: u64, 
        secondary_id: u64,
        max_checkpoint_id: u64
    ) -> anyhow::Result<Option<QDatabaseDoubleIdTableRow<V>>> {
        let res = session.execute_unpaged(&self.select_value_checkpoint_id_obj_ids_1_prepared, (u64_to_i64_exact(obj_id), u64_to_i64_exact(secondary_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, i64, i64, Vec<u8>)>()? {
            Some(row) => Ok(Some(QDatabaseDoubleIdTableRow {
                value: V::psy_ser_from_owned_bytes_vec(row.3)?,
                obj_id: i64_to_u64_exact(row.0),
                secondary_id: i64_to_u64_exact(row.1),
                checkpoint_id: convert_i64_to_checkpoint_id(row.2),
                })),
            None => Ok(None), // Return zero hash if not found
        }
    }
    pub async fn select_one_double_checkpointed_object_value_and_ids_t<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseDoubleIdTableRowCreatable<V>>(
        &self, 
        session: &Session, 
        obj_id: u64, 
        secondary_id: u64,
        max_checkpoint_id: u64
    ) -> anyhow::Result<Option<R>> {
        let res = session.execute_unpaged(&self.select_value_checkpoint_id_obj_ids_1_prepared, (u64_to_i64_exact(obj_id), u64_to_i64_exact(secondary_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, i64, i64, Vec<u8>)>()? {
            Some(row) => Ok(Some(R::create_from_double_row(i64_to_u64_exact(row.0), i64_to_u64_exact(row.1), convert_i64_to_checkpoint_id(row.2), V::psy_ser_from_owned_bytes_vec(row.3)?))),
            None => Ok(None), // Return zero hash if not found
        }
    }
    pub async fn select_all_double_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
    ) -> anyhow::Result<Vec<QDatabaseDoubleIdTableRow<V>>> {
        let res = session.execute_unpaged(&self.select_all_prepared, ()).await?;
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
                value: V::psy_ser_from_owned_bytes_vec(value)?,
            });
        }
        Ok(results)
    }


    pub async fn insert_one_double_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        obj_id: u64, 
        secondary_id: u64,
        checkpoint_id: u64, 
        value: &V
    ) -> anyhow::Result<()> {
        let value_bytes = value.psy_ser_to_bytes_vec()?;
        session.execute_unpaged(&self.insert_1_prepared, (u64_to_i64_exact(obj_id), u64_to_i64_exact(secondary_id), u64_to_i64_exact(checkpoint_id), &value_bytes)).await?;
        Ok(())
    }
    pub async fn insert_many_double_checkpointed_object_rows<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        rows: &[QDatabaseDoubleIdTableRow<V>]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.obj_id), u64_to_i64_exact(n.secondary_id), convert_checkpoint_id_to_i64(n.checkpoint_id), n.value.psy_ser_to_bytes_vec()?))
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

    pub async fn insert_many_double_checkpointed_object_rows_t<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseDoubleIdTableRowLike<V>>(
        &self, 
        session: &Session, 
        rows: &[R]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.get_row_obj_id()), u64_to_i64_exact(n.get_row_secondary_id()), convert_checkpoint_id_to_i64(n.get_row_checkpoint_id()), n.get_row_value_ref().psy_ser_to_bytes_vec()?))
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
    pub async fn insert_many_double_checkpointed_objects_at_checkpoint<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        checkpoint_id: u64,
        rows: &[QDatabaseDoubleIdTableRowNoCheckpointId<V>]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.obj_id), u64_to_i64_exact(n.secondary_id), convert_checkpoint_id_to_i64(checkpoint_id), n.value.psy_ser_to_bytes_vec()?))
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
    pub async fn insert_many_double_checkpointed_objects_at_checkpoint_t<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseDoubleIdTableRowNoCheckpointIdLike<V>>(
        &self, 
        session: &Session, 
        checkpoint_id: u64,
        rows: &[R]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.get_row_obj_id()), u64_to_i64_exact(n.get_row_secondary_id()), convert_checkpoint_id_to_i64(checkpoint_id), n.get_row_value_ref().psy_ser_to_bytes_vec()?))
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
    pub async fn select_many_double_checkpointed_object_values<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64
    ) -> anyhow::Result<Vec<Option<V>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
        for chunk in obj_ids.chunks(SELECT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    
                    let prep = self.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (u64_to_i64_exact(key.obj_id), u64_to_i64_exact(key.secondary_id), max_cp_i64)).await?;
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
    pub async fn select_many_double_checkpointed_object_keys_and_values<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseDoubleIdTableRowCreatable<V>>(
        &self, 
        session: &Session, 
        obj_ids: &[QDoubleIdKey], 
        max_checkpoint_id: u64
    ) -> anyhow::Result<Vec<R>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
        for chunk in obj_ids.chunks(SELECT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    
                    let prep = self.select_value_checkpoint_id_obj_ids_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (u64_to_i64_exact(key.obj_id), u64_to_i64_exact(key.secondary_id), max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(i64, i64, i64, Vec<u8>)>()? {
                            anyhow::Ok(Some(R::create_from_double_row(i64_to_u64_exact(row.0), i64_to_u64_exact(row.1), convert_i64_to_checkpoint_id(row.2), V::psy_ser_from_owned_bytes_vec(row.3)?)))
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