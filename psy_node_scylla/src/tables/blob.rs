use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use futures::future::join_all;
use parth_core::data::db::{data_types::{BiDirectionalMappingRow, QDatabasePrimitiveKey}, table::QDatabaseTableRoutingKey};
use scylla::{client::session::Session, statement::{batch::Batch, prepared::PreparedStatement, Statement}};

use crate::{constants::{INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE, SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE}, tables::traits::ScyllaStandardPreparedTableStatements};


#[derive(Clone)]
pub struct ScyllaBlobToBlobTablePreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,

    pub select_value_1_statement: Statement,
    pub select_value_1_prepared: Arc<PreparedStatement>,
    pub select_key_value_1_statement: Statement,
    pub select_key_value_1_prepared: Arc<PreparedStatement>,

    pub select_all_statement: Statement,
    pub select_all_prepared: Arc<PreparedStatement>,

    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
}

impl ScyllaBlobToBlobTablePreparedStatements {
    pub async fn new_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(format!("INSERT INTO {}.{} (obj_id, value) VALUES (?, ?)", keyspace, table_name));
        let insert_1_prepared = session.prepare(insert_1_statement.clone()).await?;

        let select_value_1_statement = Statement::new(format!("SELECT value FROM {}.{} WHERE obj_id = ? LIMIT 1", keyspace, table_name));
        let select_value_1_prepared = session.prepare(select_value_1_statement.clone()).await?;

        let select_key_value_1_statement = Statement::new(format!("SELECT obj_id, value FROM {}.{} WHERE obj_id = ? LIMIT 1", keyspace, table_name));
        let select_key_value_1_prepared = session.prepare(select_key_value_1_statement.clone()).await?;

        let select_all_statement = Statement::new(format!("SELECT obj_id, value FROM {}.{}", keyspace, table_name));
        let select_all_prepared = session.prepare(select_all_statement.clone()).await?;

        Ok(Self {
            insert_1_statement: insert_1_statement,
            insert_1_prepared: Arc::new(insert_1_prepared),
            select_value_1_statement: select_value_1_statement,
            select_value_1_prepared: Arc::new(select_value_1_prepared),
            select_key_value_1_statement: select_key_value_1_statement,
            select_key_value_1_prepared: Arc::new(select_key_value_1_prepared),
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
                format!(
                    "CREATE TABLE IF NOT EXISTS {}.{} (
                    obj_id blob,
                    value blob,
                    PRIMARY KEY ((obj_id))
                )",
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

    pub async fn set_or_insert_one(&self, session: Arc<Session>, obj_id: &[u8], value: &[u8]) -> anyhow::Result<()> {
        session
            .execute_unpaged(&self.insert_1_prepared, (obj_id, value))
            .await?;
        Ok(())
    }
    pub async fn set_or_insert_one_qpk<K: QDatabasePrimitiveKey, V: QDatabasePrimitiveKey>(&self, session: Arc<Session>, obj_id: &K, value: &V) -> anyhow::Result<()> {
        session
            .execute_unpaged(&self.insert_1_prepared, (obj_id.psy_ser_to_bytes_vec()?, value.psy_ser_to_bytes_vec()?))
            .await?;
        Ok(())
    }
    pub async fn select_one_single_qpk<K: QDatabasePrimitiveKey, V: QDatabasePrimitiveKey>(&self, session: Arc<Session>, obj_id: &K) -> anyhow::Result<Option<V>> {
        let res = session
            .execute_unpaged(&self.select_value_1_prepared, (obj_id.psy_ser_to_bytes_vec()?,))
            .await?;
        let value = res.into_rows_result()?.maybe_first_row::<(Option<Vec<u8>>,)>()?.map(|(val,)| val);
        if value.is_none() {
            return Ok(None);
        }else{
            let value = value.unwrap();
            if value.is_none() {
                return Ok(None);
            }else{
                let value = value.unwrap();
                Ok(Some(V::psy_ser_from_owned_bytes_vec(value)?))
            }
        }
    }
    pub async fn select_one_single(&self, session: Arc<Session>, obj_id: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let res = session
            .execute_unpaged(&self.select_value_1_prepared, (obj_id,))
            .await?;
        let value = res.into_rows_result()?.maybe_first_row::<(Option<Vec<u8>>,)>()?.map(|(val,)| val);
        if value.is_some() {
            Ok(value.unwrap())
        } else {
            Ok(None)
        }
    }
    pub async fn set_or_insert_many_qpk<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, session: Arc<Session>, entries: &[BiDirectionalMappingRow<K1, K2>], swap_kv: bool) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value

        let chunk_size = INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE;
        let mut value_list = Vec::with_capacity(entries.len());
        for chunk in entries.chunks(chunk_size) {
            let mut batch: Batch = Default::default();
            let mut value_chunk = Vec::with_capacity(chunk.len());
            for chk in chunk.iter() {
                if swap_kv {
                    value_chunk.push((chk.k2.psy_ser_to_bytes_vec()?, chk.k1.psy_ser_to_bytes_vec()?));
                } else {
                    value_chunk.push((chk.k1.psy_ser_to_bytes_vec()?, chk.k2.psy_ser_to_bytes_vec()?));
                }
                batch.append_statement(self.insert_1_statement.clone());
            }
            batch_list.push(batch);
            value_list.push(value_chunk);
        }
        let batches: Vec<_> = batch_list
            .iter()
            .zip(value_list.iter())
            .map(|(batch, values)| session.batch(batch, values))
            .collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }
    pub async fn set_or_insert_many(&self, session: Arc<Session>, entries: Vec<(Vec<u8>, Vec<u8>)>) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value

        let chunk_size = INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE;
        for chunk in entries.chunks(chunk_size) {
            let mut batch: Batch = Default::default();
            for _ in 0..chunk.len() {
                batch.append_statement(self.insert_1_statement.clone());
            }
            batch_list.push(batch);
        }
        
        let batches: Vec<_> = batch_list
            .iter()
            .zip(entries.chunks(chunk_size).into_iter())
            .map(|(batch, values)| session.batch(batch, values))
            .collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }
    pub async fn select_many_values_ref(&self, session: Arc<Session>, obj_ids: &[&[u8]]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        for chunk in obj_ids.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = session.clone();
                    let prep = self.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key,)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Option<Vec<u8>>,)>()? {
                            match row.0 {
                                Some(v) => anyhow::Ok(Some(v)),
                                None => Ok(None),
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
    pub async fn select_many_values_qpk<K: QDatabasePrimitiveKey, V: QDatabasePrimitiveKey>(&self, session: Arc<Session>, obj_ids: &[K]) -> anyhow::Result<Vec<Option<V>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let obj_id_bytes: Vec<Vec<u8>> = obj_ids.iter().map(|k| k.psy_ser_to_bytes_vec()).collect::<Result<_, _>>()?;
        for chunk in obj_id_bytes.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = session.clone();
                    let prep = self.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (key.as_slice(),)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Option<Vec<u8>>,)>()? {
                            match row.0 {
                                Some(v) => anyhow::Ok(Some(V::psy_ser_from_owned_bytes_vec(v)?),),
                                None => Ok(None),
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
    pub async fn select_many_key_values_qpk<K: QDatabasePrimitiveKey, V: QDatabasePrimitiveKey>(&self, session: Arc<Session>, obj_ids: &[K]) -> anyhow::Result<Vec<BiDirectionalMappingRow<K,V>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        for chunk in obj_ids.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = session.clone();
                    let prep = self.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (key.psy_ser_to_bytes_vec()?,)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Option<Vec<u8>>,)>()? {
                            match row.0 {
                                Some(v) => anyhow::Ok(Some(BiDirectionalMappingRow{
                                    k1: key.clone(),
                                    k2: V::psy_ser_from_owned_bytes_vec(v)?
                            }),),
                                None => Ok(None),
                            }
                        } else {
                            Ok(None)
                        }
                    }
                })
                .collect();
            let chunk_results = join_all(futures).await;
            for res in chunk_results {
                let q = res?;
                if q.is_some(){
                    results.push(q.unwrap());
                }
            }
        }
        Ok(results)
    }
    pub async fn select_many_values_sized<const KS: usize>(&self, session: Arc<Session>, obj_ids: &[[u8; KS]]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        for chunk in obj_ids.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = session.clone();
                    let prep = self.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key,)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Option<Vec<u8>>,)>()? {
                            match row.0 {
                                Some(v) => anyhow::Ok(Some(v)),
                                None => Ok(None),
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
    pub async fn select_many_values_dual_sized<const KS: usize, const VS: usize>(&self, session: Arc<Session>, obj_ids: &[[u8; KS]]) -> anyhow::Result<Vec<Option<[u8; VS]>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        for chunk in obj_ids.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = session.clone();
                    let prep = self.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key,)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Option<Vec<u8>>,)>()? {
                            match row.0 {
                                Some(v) => {
                                    if v.len() != VS {
                                        anyhow::bail!("Value length mismatch: expected {}, got {}", VS, v.len());
                                    }
                                    let mut arr = [0u8; VS];
                                    arr.copy_from_slice(&v);
                                    Ok(Some(arr))
                                }
                                None => Ok(None),
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
}

#[async_trait]
impl ScyllaStandardPreparedTableStatements for ScyllaBlobToBlobTablePreparedStatements {
    async fn create_table_standard(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::new_create_from_session(session, keyspace, table_name, table_key).await
    }
}


#[derive(Clone)]
pub struct ScyllaBiDirectionalBlobToBlobTablePreparedStatements {
    pub k1: ScyllaBlobToBlobTablePreparedStatements,
    pub k2: ScyllaBlobToBlobTablePreparedStatements,
}

impl ScyllaBiDirectionalBlobToBlobTablePreparedStatements {
    pub async fn new_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name_k1: &str,
        table_name_k2: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        let k1 = ScyllaBlobToBlobTablePreparedStatements::new_from_session(session.clone(), keyspace, table_name_k1, table_key.clone()).await?;
        let k2 = ScyllaBlobToBlobTablePreparedStatements::new_from_session(session.clone(), keyspace, table_name_k2, table_key.clone()).await?;
        Ok(Self { k1, k2 })
    }
    pub async fn create_table(session: Arc<Session>, keyspace: &str, table_name_k1: &str, table_name_k2: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<()> {
        ScyllaBlobToBlobTablePreparedStatements::create_table(session.clone(), keyspace, table_name_k1, table_key.clone()).await?;
        ScyllaBlobToBlobTablePreparedStatements::create_table(session.clone(), keyspace, table_name_k2, table_key.clone()).await?;
        Ok(())
    }
    pub async fn new_create_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name_k1: &str,
        table_name_k2: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::create_table(session.clone(), keyspace, table_name_k1, table_name_k2, table_key.clone()).await?;
        Self::new_from_session(session, keyspace, table_name_k1, table_name_k2, table_key).await
    }
}

impl ScyllaBiDirectionalBlobToBlobTablePreparedStatements {
    pub async fn set_or_insert_many_qpk<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, session: Arc<Session>, entries: &[BiDirectionalMappingRow<K1, K2>]) -> anyhow::Result<()> {
        self.k1.set_or_insert_many_qpk(session.clone(), entries, false).await?;
        self.k2.set_or_insert_many_qpk(session.clone(), entries, true).await?;
        Ok(())
    }
    pub async fn set_or_insert_many(&self, session: Arc<Session>, entries: Vec<(Vec<u8>, Vec<u8>)>) -> anyhow::Result<()> {
        let rev_entries: Vec<(Vec<u8>, Vec<u8>)> = entries.iter().map(|(k, v)| (v.clone(), k.clone())).collect();
        self.k1.set_or_insert_many(session.clone(), entries).await?;
        self.k2.set_or_insert_many(session.clone(), rev_entries).await?;
        Ok(())
    }
    pub async fn set_or_insert_one_qpk<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, session: Arc<Session>, k1: &K1, k2: &K2) -> anyhow::Result<()> {
        self.k1.set_or_insert_one_qpk(session.clone(), k1, k2).await?;
        self.k2.set_or_insert_one_qpk(session.clone(), k2, k1).await?;
        Ok(())
    }
    pub async fn select_one_by_k1<K: QDatabasePrimitiveKey, V: QDatabasePrimitiveKey>(&self, session: Arc<Session>, k1: &K) -> anyhow::Result<Option<V>> {
        self.k1.select_one_single_qpk(session, k1).await
    }
    pub async fn select_one_by_k2<K: QDatabasePrimitiveKey, V: QDatabasePrimitiveKey>(&self, session: Arc<Session>, k2: &K) -> anyhow::Result<Option<V>> {
        self.k2.select_one_single_qpk(session, k2).await
    }
    pub async fn select_many_by_k1<K: QDatabasePrimitiveKey, V: QDatabasePrimitiveKey>(&self, session: Arc<Session>, k1s: &[K]) -> anyhow::Result<Vec<Option<V>>> {
        self.k1.select_many_values_qpk(session, k1s).await
    }
    pub async fn select_many_by_k2<K: QDatabasePrimitiveKey, V: QDatabasePrimitiveKey>(&self, session: Arc<Session>, k2s: &[K]) -> anyhow::Result<Vec<Option<V>>> {
        self.k2.select_many_values_qpk(session, k2s).await
    }
    pub async fn select_many_key_values_by_k1<K: QDatabasePrimitiveKey, V: QDatabasePrimitiveKey>(&self, session: Arc<Session>, k1s: &[K]) -> anyhow::Result<Vec<BiDirectionalMappingRow<K,V>>> {
        self.k1.select_many_key_values_qpk(session, k1s).await
    }
    pub async fn select_many_key_values_by_k2<K: QDatabasePrimitiveKey, V: QDatabasePrimitiveKey>(&self, session: Arc<Session>, k2s: &[K]) -> anyhow::Result<Vec<BiDirectionalMappingRow<V,K>>> {
        Ok(self.k2.select_many_key_values_qpk(session, k2s).await?.into_iter().map(|r| BiDirectionalMappingRow{
            k1: r.k2,
            k2: r.k1
        }).collect::<Vec<_>>())
    }
}

#[async_trait]
impl ScyllaStandardPreparedTableStatements for ScyllaBiDirectionalBlobToBlobTablePreparedStatements {
    async fn create_table_standard(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        let table_name_k1 = format!("{}_k1", table_name);
        let table_name_k2 = format!("{}_k2", table_name);
        Self::new_create_from_session(session, keyspace, &table_name_k1, &table_name_k2, table_key).await
    }
}