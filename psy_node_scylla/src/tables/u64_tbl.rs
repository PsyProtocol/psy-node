use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use futures::future::join_all;
use parth_core::data::{db::{data_types::BiDirectionalMappingRow, table::QDatabaseTableRoutingKey}, serializable::QPDPair};
use scylla::{
    client::session::Session,
    statement::{batch::Batch, prepared::PreparedStatement, Statement},
};
use tokio::time::sleep;
use uuid::Uuid;

use crate::{
    constants::{INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE, SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE},
    tables::traits::ScyllaStandardPreparedTableStatements,
    utils::{i64_to_u64_exact, u64_to_i64_exact},
};

#[derive(Clone)]
pub struct ScyllaU64ToU64TablePreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,

    pub select_value_1_statement: Statement,
    pub select_value_1_prepared: Arc<PreparedStatement>,

    pub update_if_exists_statement: Statement,
    pub update_if_exists_prepared: Arc<PreparedStatement>,

    pub insert_if_not_exists_statement: Statement,
    pub insert_if_not_exists_prepared: Arc<PreparedStatement>,

    pub select_all_statement: Statement,
    pub select_all_prepared: Arc<PreparedStatement>,

    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
}

impl ScyllaU64ToU64TablePreparedStatements {
    pub async fn new_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(format!("INSERT INTO {}.{} (obj_id, value) VALUES (?, ?)", keyspace, table_name));
        let insert_1_prepared = session.prepare(insert_1_statement.clone()).await?;

        let select_value_1_statement = Statement::new(format!("SELECT value FROM {}.{} WHERE obj_id = ?", keyspace, table_name));
        let select_value_1_prepared = session.prepare(select_value_1_statement.clone()).await?;

        let select_all_statement = Statement::new(format!("SELECT obj_id, value FROM {}.{}", keyspace, table_name));
        let select_all_prepared = session.prepare(select_all_statement.clone()).await?;

        let update_if_exists_statement = Statement::new(format!("UPDATE {}.{} SET value = ? WHERE obj_id = ? IF value = ?", keyspace, table_name));
        let update_if_exists_prepared = session.prepare(update_if_exists_statement.clone()).await?;

        let insert_if_not_exists_statement = Statement::new(format!(
            "INSERT INTO {}.{} (obj_id, value) VALUES (?, ?) IF NOT EXISTS",
            keyspace, table_name
        ));
        let insert_if_not_exists_prepared = session.prepare(insert_if_not_exists_statement.clone()).await?;

        Ok(Self {
            insert_1_statement: insert_1_statement,
            insert_1_prepared: Arc::new(insert_1_prepared),
            select_value_1_statement: select_value_1_statement,
            select_value_1_prepared: Arc::new(select_value_1_prepared),
            select_all_statement: select_all_statement,
            select_all_prepared: Arc::new(select_all_prepared),
            update_if_exists_statement: update_if_exists_statement,
            update_if_exists_prepared: Arc::new(update_if_exists_prepared),
            insert_if_not_exists_statement: insert_if_not_exists_statement,
            insert_if_not_exists_prepared: Arc::new(insert_if_not_exists_prepared),
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
                    obj_id BIGINT,
                    value BIGINT,
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
}
#[async_trait]
impl ScyllaStandardPreparedTableStatements for ScyllaU64ToU64TablePreparedStatements {
    async fn create_table_standard(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::new_create_from_session(session, keyspace, table_name, table_key).await
    }
}

impl ScyllaU64ToU64TablePreparedStatements {
    pub async fn atomic_increment(&self, session: &Session, obj_id: u64, amount: u64) -> anyhow::Result<u64> {
        let obj_id_i64 = u64_to_i64_exact(obj_id);
        loop {
            let res = session
                .execute_unpaged(&self.select_value_1_prepared, (obj_id_i64,))
                .await?;
            let current_value_i64 = res
                .into_rows_result()?
                .maybe_first_row::<(Option<i64>,)>()?
                .map(|(val,)| val.unwrap_or(0));
            let current_value_u64 = i64_to_u64_exact(current_value_i64.unwrap_or(0));

            let new_value_i64 = u64_to_i64_exact(current_value_u64)+ u64_to_i64_exact(amount);
            let new_value_u64 = i64_to_u64_exact(new_value_i64);
            if current_value_i64.is_some() {
                let update_result = session
                    .execute_unpaged(&self.update_if_exists_prepared, (new_value_i64, obj_id_i64, current_value_i64.unwrap()))
                    .await?;
                let applied = update_result.into_rows_result()?.first_row::<(bool,i64)>()?.0;
                if applied {
                    return Ok(new_value_u64);
                }
            } else {
                let insert_result = session
                    .execute_unpaged(&self.insert_if_not_exists_prepared, (obj_id_i64, new_value_i64))
                    .await?;
                let applied = insert_result.into_rows_result()?.first_row::<(bool,Option<i64>, Option<i64>)>()?.0;
                if applied {
                    return Ok(new_value_u64);
                }
            }
            // Else retry (row was created concurrently)
            sleep(std::time::Duration::from_millis(10 + rand::random::<u64>() % 100)).await;
        }
    }
    pub async fn select_one_single(&self, session: &Session, obj_id: u64) -> anyhow::Result<Option<u64>> {
        let res = session
            .execute_unpaged(&self.select_value_1_prepared, (u64_to_i64_exact(obj_id),))
            .await?;
        let current_value_i64 = res.into_rows_result()?.maybe_first_row::<(Option<i64>,)>()?.map(|(val,)| val);
        if current_value_i64.is_none() || current_value_i64.unwrap().is_none() {
            return Ok(None);
        }
        let current_value_u64 = i64_to_u64_exact(current_value_i64.unwrap().unwrap());
        Ok(Some(current_value_u64))
    }
    pub async fn set_or_insert_one(&self, session: &Session, obj_id: u64, value: u64) -> anyhow::Result<()> {
        let obj_id_i64 = u64_to_i64_exact(obj_id);
        let value_i64 = u64_to_i64_exact(value);
        session.execute_unpaged(&self.insert_1_prepared, (obj_id_i64, value_i64)).await?;
        Ok(())
    }
    pub async fn set_or_insert_many(&self, session: &Session, entries: &[(u64, u64)]) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let value_list: Vec<Vec<(i64, i64)>> = entries
            .iter()
            .map(|x| (u64_to_i64_exact(x.0), u64_to_i64_exact(x.1)))
            .collect::<Vec<_>>()
            .chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE)
            .map(|x| x.to_vec())
            .collect();
        let chunk_lens = value_list.iter().map(|x| x.len()).collect::<Vec<_>>();
        for chunk_len in chunk_lens.into_iter() {
            let mut batch: Batch = Default::default();
            for _ in 0..chunk_len {
                batch.append_statement(self.insert_1_statement.clone());
            }

            batch_list.push(batch);
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
    pub async fn set_or_insert_many_qpd_pair(&self, session: &Session, entries: &[QPDPair<u64, u64>]) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let value_list: Vec<Vec<(i64, i64)>> = entries
            .iter()
            .map(|x| (u64_to_i64_exact(x.key), u64_to_i64_exact(x.value)))
            .collect::<Vec<_>>()
            .chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE)
            .map(|x| x.to_vec())
            .collect();
        let chunk_lens = value_list.iter().map(|x| x.len()).collect::<Vec<_>>();
        for chunk_len in chunk_lens.into_iter() {
            let mut batch: Batch = Default::default();
            for _ in 0..chunk_len {
                batch.append_statement(self.insert_1_statement.clone());
            }

            batch_list.push(batch);
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


    pub async fn select_many_values(&self, session: Arc<Session>, obj_ids: &[u64]) -> anyhow::Result<Vec<Option<u64>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let obj_ids_i64 = obj_ids.iter().map(|id| u64_to_i64_exact(*id)).collect::<Vec<_>>();
        for chunk in obj_ids_i64.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = session.clone();
                    let prep = self.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key,)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Option<i64>,)>()? {
                            match row.0 {
                                Some(uuid) => anyhow::Ok(Some(i64_to_u64_exact(uuid))),
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

#[derive(Clone)]
pub struct ScyllaU128ToU64TablePreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,

    pub select_value_1_statement: Statement,
    pub select_value_1_prepared: Arc<PreparedStatement>,

    pub select_all_statement: Statement,
    pub select_all_prepared: Arc<PreparedStatement>,

    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
}

impl ScyllaU128ToU64TablePreparedStatements {
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

        let select_all_statement = Statement::new(format!("SELECT obj_id, value FROM {}.{}", keyspace, table_name));
        let select_all_prepared = session.prepare(select_all_statement.clone()).await?;

        Ok(Self {
            insert_1_statement: insert_1_statement,
            insert_1_prepared: Arc::new(insert_1_prepared),
            select_value_1_statement: select_value_1_statement,
            select_value_1_prepared: Arc::new(select_value_1_prepared),
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
                    obj_id UUID,
                    value BIGINT,
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

    pub async fn set_or_insert_one(&self, session: &Session, obj_id: u128, value: u64) -> anyhow::Result<()> {
        let value_i64 = u64_to_i64_exact(value);
        let obj_id_uuid = Uuid::from_u128(obj_id);

        session.execute_unpaged(&self.insert_1_prepared, (obj_id_uuid, value_i64)).await?;
        Ok(())
    }
    pub async fn select_one_single(&self, session: &Session, obj_id: u128) -> anyhow::Result<Option<u64>> {
        let obj_id_uuid = Uuid::from_u128(obj_id);
        let res = session.execute_unpaged(&self.select_value_1_prepared, (obj_id_uuid,)).await?;
        let current_value_uuid = res.into_rows_result()?.maybe_first_row::<(Option<i64>,)>()?.map(|(val,)| val);
        let current_value_u64 = current_value_uuid.map(|v| v.map(|x| i64_to_u64_exact(x))).unwrap_or(None);
        Ok(current_value_u64)
    }
    pub async fn select_many_values(&self, session: Arc<Session>, obj_ids: &[u128]) -> anyhow::Result<Vec<Option<u64>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let obj_ids_i64 = obj_ids.iter().map(|id| Uuid::from_u128(*id)).collect::<Vec<_>>();
        for chunk in obj_ids_i64.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = session.clone();
                    let prep = self.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key,)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Option<i64>,)>()? {
                            match row.0 {
                                Some(num) => anyhow::Ok(Some(i64_to_u64_exact(num))),
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
    pub async fn set_or_insert_many(&self, session: &Session, entries: &[(u128, u64)]) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let value_list: Vec<Vec<(Uuid, i64)>> = entries
            .iter()
            .map(|x| (Uuid::from_u128(x.0), u64_to_i64_exact(x.1)))
            .collect::<Vec<_>>()
            .chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE)
            .map(|x| x.to_vec())
            .collect();
        let chunk_lens = value_list.iter().map(|x| x.len()).collect::<Vec<_>>();
        for chunk_len in chunk_lens.into_iter() {
            let mut batch: Batch = Default::default();
            for _ in 0..chunk_len {
                batch.append_statement(self.insert_1_statement.clone());
            }

            batch_list.push(batch);
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

#[async_trait]
impl ScyllaStandardPreparedTableStatements for ScyllaU128ToU64TablePreparedStatements {
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
pub struct ScyllaU64ToU128TablePreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,

    pub select_value_1_statement: Statement,
    pub select_value_1_prepared: Arc<PreparedStatement>,

    pub select_all_statement: Statement,
    pub select_all_prepared: Arc<PreparedStatement>,

    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
}

impl ScyllaU64ToU128TablePreparedStatements {
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

        let select_all_statement = Statement::new(format!("SELECT obj_id, value FROM {}.{}", keyspace, table_name));
        let select_all_prepared = session.prepare(select_all_statement.clone()).await?;

        Ok(Self {
            insert_1_statement: insert_1_statement,
            insert_1_prepared: Arc::new(insert_1_prepared),
            select_value_1_statement: select_value_1_statement,
            select_value_1_prepared: Arc::new(select_value_1_prepared),
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
                    obj_id BIGINT,
                    value UUID,
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

    pub async fn set_or_insert_one(&self, session: &Session, obj_id: u64, value: u128) -> anyhow::Result<()> {
        let obj_id_i64 = u64_to_i64_exact(obj_id);
        session
            .execute_unpaged(&self.insert_1_prepared, (obj_id_i64, Uuid::from_u128(value)))
            .await?;
        Ok(())
    }
    pub async fn select_one_single(&self, session: &Session, obj_id: u64) -> anyhow::Result<Option<u128>> {
        let res = session
            .execute_unpaged(&self.select_value_1_prepared, (u64_to_i64_exact(obj_id),))
            .await?;
        let current_value_uuid = res.into_rows_result()?.maybe_first_row::<(Option<Uuid>,)>()?.map(|(val,)| val);
        let current_value_u128 = current_value_uuid.map(|v| v.map(|x| x.as_u128())).unwrap_or(None);
        Ok(current_value_u128)
    }
    pub async fn set_or_insert_many(&self, session: &Session, entries: &[(u64, u128)]) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let value_list: Vec<Vec<(i64, Uuid)>> = entries
            .iter()
            .map(|x| (u64_to_i64_exact(x.0), Uuid::from_u128(x.1)))
            .collect::<Vec<_>>()
            .chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE)
            .map(|x| x.to_vec())
            .collect();
        let chunk_lens = value_list.iter().map(|x| x.len()).collect::<Vec<_>>();
        for chunk_len in chunk_lens.into_iter() {
            let mut batch: Batch = Default::default();
            for _ in 0..chunk_len {
                batch.append_statement(self.insert_1_statement.clone());
            }

            batch_list.push(batch);
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
    pub async fn select_many_values(&self, session: Arc<Session>, obj_ids: &[u64]) -> anyhow::Result<Vec<Option<u128>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let obj_ids_i64 = obj_ids.iter().map(|id| u64_to_i64_exact(*id)).collect::<Vec<_>>();
        for chunk in obj_ids_i64.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = session.clone();
                    let prep = self.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key,)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Option<Uuid>,)>()? {
                            match row.0 {
                                Some(uuid) => anyhow::Ok(Some(uuid.as_u128())),
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
impl ScyllaStandardPreparedTableStatements for ScyllaU64ToU128TablePreparedStatements {
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
pub struct ScyllaBidirectionalU64U128MappingPreparedStatements {
    pub u64_to_u128: ScyllaU64ToU128TablePreparedStatements,
    pub u128_to_u64: ScyllaU128ToU64TablePreparedStatements,
}

impl ScyllaBidirectionalU64U128MappingPreparedStatements {
    pub async fn new_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name_u64_to_u128: &str,
        table_name_u128_to_u64: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        let u64_to_u128 = ScyllaU64ToU128TablePreparedStatements::new_from_session(
            session.clone(),
            keyspace,
            table_name_u64_to_u128,
            table_key.clone(),
        )
        .await?;
        let u128_to_u64 = ScyllaU128ToU64TablePreparedStatements::new_from_session(
            session.clone(),
            keyspace,
            table_name_u128_to_u64,
            table_key.clone(),
        )
        .await?;
        Ok(Self {
            u64_to_u128,
            u128_to_u64,
        })
    }
    pub async fn create_tables(
        session: Arc<Session>,
        keyspace: &str,
        table_name_u64_to_u128: &str,
        table_name_u128_to_u64: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<()> {
        ScyllaU64ToU128TablePreparedStatements::create_table(session.clone(), keyspace, table_name_u64_to_u128, table_key.clone()).await?;
        ScyllaU128ToU64TablePreparedStatements::create_table(session.clone(), keyspace, table_name_u128_to_u64, table_key.clone()).await?;
        Ok(())
    }
    pub async fn new_create_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name_u64_to_u128: &str,
        table_name_u128_to_u64: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::create_tables(
            session.clone(),
            keyspace,
            table_name_u64_to_u128,
            table_name_u128_to_u64,
            table_key.clone(),
        )
        .await?;
        Self::new_from_session(
            session.clone(),
            keyspace,
            table_name_u64_to_u128,
            table_name_u128_to_u64,
            table_key.clone(),
        )
        .await
    }
}



#[async_trait]
impl ScyllaStandardPreparedTableStatements for ScyllaBidirectionalU64U128MappingPreparedStatements {
    async fn create_table_standard(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::new_create_from_session(
            session,
            keyspace,
            &format!("{}_u64_to_u128", table_name),
            &format!("{}_u128_to_u64", table_name),
            table_key,
        )
        .await
    }
}

impl ScyllaBidirectionalU64U128MappingPreparedStatements {
    pub async fn insert_u64_u128_mapping_pair(&self, session: &Session, k1: u64, k2: u128) -> anyhow::Result<()> {
        let fut1 = self.u64_to_u128.set_or_insert_one(session, k1, k2);
        let fut2 = self.u128_to_u64.set_or_insert_one(session, k2, k1);
        let (res1, res2) = tokio::join!(fut1, fut2);
        res1?;
        res2?;
        Ok(())
    }
    pub async fn insert_u64_u128_mapping_pairs(&self, session: &Session, keys: &[BiDirectionalMappingRow<u64, u128>]) -> anyhow::Result<()> {
        let entries_1: Vec<(u64, u128)> = keys.iter().map(|x| (x.k1.clone(), x.k2.clone())).collect();
        let entries_2: Vec<(u128, u64)> = keys.iter().map(|x| (x.k2.clone(), x.k1.clone())).collect();
        let fut1 = self.u64_to_u128.set_or_insert_many(session, &entries_1);
        let fut2 = self.u128_to_u64.set_or_insert_many(session, &entries_2);
        let (res1, res2) = tokio::join!(fut1, fut2);
        res1?;
        res2?;
        Ok(())
    }
    pub async fn get_k2_from_k1(&self, session: &Session, k1: u64) -> anyhow::Result<Option<u128>> {
        self.u64_to_u128.select_one_single(session, k1).await
    }
    pub async fn get_k1_from_k2(&self, session: &Session, k2: u128) -> anyhow::Result<Option<u64>> {
        self.u128_to_u64.select_one_single(session, k2).await
    }
    pub async fn get_k2s_from_k1s(&self, session: Arc<Session>, k1s: &[u64]) -> anyhow::Result<Vec<Option<u128>>> {
        self.u64_to_u128.select_many_values(session, k1s).await
    }
    pub async fn get_k1s_from_k2s(&self, session: Arc<Session>, k2s: &[u128]) -> anyhow::Result<Vec<Option<u64>>> {
        self.u128_to_u64.select_many_values(session, k2s).await
    }
}
