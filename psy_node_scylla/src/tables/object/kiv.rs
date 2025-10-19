use std::sync::Arc;
use anyhow::Context;
use async_trait::async_trait;
use futures::future::join_all;
use parth_core::data::db::{row::{QDatabaseKeyIdValueTableRow, QDatabaseKeyIdValueTableRowCreatable, QDatabaseKeyIdValueTableRowLike}, table::QDatabaseTableRoutingKey};
use psy_serialize::PsySerializeCanonicalAsyncSafe;
use scylla::{client::session::Session, statement::{batch::Batch, prepared::PreparedStatement, Statement}};

use crate::{constants::{INSERT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE, SELECT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE}, tables::traits::ScyllaStandardPreparedTableStatements, utils::{i64_to_u64_exact, u64_to_i64_exact}};





#[derive(Clone)]
pub struct ScyllaGenericKeyIdValueTablePreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,
    
    pub select_value_1_statement: Statement,
    pub select_value_1_prepared: Arc<PreparedStatement>,

    pub select_value_obj_id_1_statement: Statement,
    pub select_value_obj_id_1_prepared: Arc<PreparedStatement>,

    pub select_all_statement: Statement,
    pub select_all_prepared: Arc<PreparedStatement>,

    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
}

impl ScyllaGenericKeyIdValueTablePreparedStatements {
    pub async fn new_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(format!("INSERT INTO {}.{} (obj_id, value) VALUES (?, ?)", keyspace, table_name));
        let insert_1_prepared = session.prepare(insert_1_statement.clone()).await?;
        
        let select_value_1_statement = Statement::new(format!("SELECT value FROM {}.{} WHERE obj_id = ? LIMIT 1", keyspace, table_name));
        let select_value_1_prepared = session.prepare(select_value_1_statement.clone()).await?;

        let select_value_obj_id_1_statement = Statement::new(format!("SELECT obj_id, value FROM {}.{} WHERE obj_id = ? LIMIT 1", keyspace, table_name));
        let select_value_obj_id_1_prepared = session.prepare(select_value_obj_id_1_statement.clone()).await?;

        let select_all_statement = Statement::new(format!("SELECT obj_id, value FROM {}.{}", keyspace, table_name));
        let select_all_prepared = session.prepare(select_all_statement.clone()).await?;

        Ok(Self {
            insert_1_statement: insert_1_statement,
            insert_1_prepared: Arc::new(insert_1_prepared),
            select_value_1_statement: select_value_1_statement,
            select_value_1_prepared: Arc::new(select_value_1_prepared),
            select_value_obj_id_1_statement: select_value_obj_id_1_statement,
            select_value_obj_id_1_prepared: Arc::new(select_value_obj_id_1_prepared),
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
                    value BLOB,
                    PRIMARY KEY ((obj_id))
                )", keyspace, table_name),
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
impl ScyllaStandardPreparedTableStatements for ScyllaGenericKeyIdValueTablePreparedStatements {
    async fn create_table_standard(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        Self::new_create_from_session(session, keyspace, table_name, table_key).await
    }
}

impl ScyllaGenericKeyIdValueTablePreparedStatements {

    pub async fn select_one_kiv_value<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        obj_id: u64
    ) -> anyhow::Result<Option<V>> {
        let res = session.execute_unpaged(&self.select_value_1_prepared, (u64_to_i64_exact(obj_id),)).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => Ok(Some(V::psy_ser_from_owned_bytes_vec(row.0)?)),
            None => Ok(None), 
        }
    }
    pub async fn select_one_kiv_value_and_ids<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        obj_id: u64
    ) -> anyhow::Result<Option<QDatabaseKeyIdValueTableRow<V>>> {
        let res = session.execute_unpaged(&self.select_value_obj_id_1_prepared, (u64_to_i64_exact(obj_id),)).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, Vec<u8>)>()? {

            Some(row) =>Ok(Some(QDatabaseKeyIdValueTableRow {
                    obj_id: i64_to_u64_exact(row.0),
                    value: V::psy_ser_from_owned_bytes_vec(row.1)?,
                })),
            None => Ok(None), // Return zero hash if not found
        }
    }
    pub async fn select_one_kiv_value_and_ids_t<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseKeyIdValueTableRowCreatable<V>>(
        &self, 
        session: &Session, 
        obj_id: u64, 
    ) -> anyhow::Result<Option<R>> {
        let res = session.execute_unpaged(&self.select_value_obj_id_1_prepared, (u64_to_i64_exact(obj_id),)).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, Vec<u8>)>()? {
            Some(row) => Ok(Some(R::create_from_key_id_value_row(i64_to_u64_exact(row.0), V::psy_ser_from_owned_bytes_vec(row.1)?))),
           
            None => Ok(None), // Return zero hash if not found
        }
    }


    
    pub async fn select_all_kiv<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
    ) -> anyhow::Result<Vec<QDatabaseKeyIdValueTableRow<V>>> {
        let res = session.execute_unpaged(&self.select_all_prepared, ()).await?;
        let rows_result = res.into_rows_result()?;
        let rows_iter = rows_result.rows::<(i64,Vec<u8>)>()?;
        let rows_vec: Vec<_> = rows_iter.collect();
        let mut results = Vec::with_capacity(rows_vec.len());

        for row in rows_vec {
            let (obj_id, value): (i64, Vec<u8>) = row?;
            results.push(QDatabaseKeyIdValueTableRow {
                obj_id: i64_to_u64_exact(obj_id),
                value: V::psy_ser_from_owned_bytes_vec(value)?,
            });
        }
        Ok(results)
    }


    pub async fn insert_one_kiv<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        obj_id: u64, 
        value: &V
    ) -> anyhow::Result<()> {
        let value_bytes = value.psy_ser_to_bytes_vec()?;
        session.execute_unpaged(&self.insert_1_prepared, (u64_to_i64_exact(obj_id), &value_bytes)).await?;
        Ok(())
    }

    pub async fn insert_many_kiv_rows_t<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseKeyIdValueTableRowLike<V>>(
        &self, 
        session: &Session, 
        rows: &[R]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.get_row_obj_id()),  n.get_row_value_ref().psy_ser_to_bytes_vec()?))
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
    pub async fn insert_many_kivs<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        rows: &[QDatabaseKeyIdValueTableRow<V>]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.obj_id), n.value.psy_ser_to_bytes_vec()?))
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
    pub async fn insert_many_kivs_t<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseKeyIdValueTableRowLike<V>>(
        &self, 
        session: &Session, 
        rows: &[R]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.get_row_obj_id()), n.get_row_value_ref().psy_ser_to_bytes_vec()?))
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
    pub async fn select_many_kiv_values<V: PsySerializeCanonicalAsyncSafe>(
        &self, 
        session: &Session, 
        obj_ids: &[u64],
    ) -> anyhow::Result<Vec<Option<V>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let obj_ids_i64 = obj_ids.iter().map(|id| u64_to_i64_exact(*id)).collect::<Vec<_>>();
        for chunk in obj_ids_i64.chunks(SELECT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    
                    let prep = self.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key,)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some((row,)) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                           anyhow::Ok(Some(V::psy_ser_from_owned_bytes_vec(row)?))
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
    pub async fn select_many_kiv_keys_and_values<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseKeyIdValueTableRowCreatable<V>>(
        &self, 
        session: &Session, 
        obj_ids: &[u64], 
    ) -> anyhow::Result<Vec<R>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let obj_ids_i64 = obj_ids.iter().map(|id| u64_to_i64_exact(*id)).collect::<Vec<_>>();
        for chunk in obj_ids_i64.chunks(SELECT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    
                    let prep = self.select_value_obj_id_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key,)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(i64, Vec<u8>)>()? {
                            anyhow::Ok(Some(R::create_from_key_id_value_row(i64_to_u64_exact(row.0), V::psy_ser_from_owned_bytes_vec(row.1)?)))
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