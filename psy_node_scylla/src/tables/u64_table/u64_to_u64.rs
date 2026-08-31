use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use futures::future::join_all;
use parth_core::data::{db::table::QDatabaseTableRoutingKey, serializable::QPDPair};
use scylla::{
    client::session::Session,
    statement::{batch::Batch, prepared::PreparedStatement, Statement},
};

use crate::{
    constants::{INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE, SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE}, table_creator::create_table_if_not_exists, tables::traits::ScyllaStandardPreparedTableStatements, utils::{i64_to_u64_exact, u64_to_i64_exact}
};

#[derive(Clone)]
pub struct ScyllaU64ToU64TablePreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,
    pub delete_1_prepared: Arc<PreparedStatement>,

    pub select_value_1_statement: Statement,
    pub select_value_1_prepared: Arc<PreparedStatement>,

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
        let delete_1_prepared = session.prepare(format!("DELETE FROM {}.{} WHERE obj_id = ?", keyspace, table_name)).await?;

        let select_value_1_statement = Statement::new(format!("SELECT value FROM {}.{} WHERE obj_id = ?", keyspace, table_name));
        let select_value_1_prepared = session.prepare(select_value_1_statement.clone()).await?;

        let select_all_statement = Statement::new(format!("SELECT obj_id, value FROM {}.{}", keyspace, table_name));
        let select_all_prepared = session.prepare(select_all_statement.clone()).await?;

        let insert_if_not_exists_statement = Statement::new(format!(
            "INSERT INTO {}.{} (obj_id, value) VALUES (?, ?) IF NOT EXISTS",
            keyspace, table_name
        ));
        let insert_if_not_exists_prepared = session.prepare(insert_if_not_exists_statement.clone()).await?;

        Ok(Self {
            insert_1_statement: insert_1_statement,
            insert_1_prepared: Arc::new(insert_1_prepared),
            delete_1_prepared: Arc::new(delete_1_prepared),
            select_value_1_statement: select_value_1_statement,
            select_value_1_prepared: Arc::new(select_value_1_prepared),
            select_all_statement: select_all_statement,
            select_all_prepared: Arc::new(select_all_prepared),
            insert_if_not_exists_statement: insert_if_not_exists_statement,
            insert_if_not_exists_prepared: Arc::new(insert_if_not_exists_prepared),
            keyspace: keyspace.to_string(),
            table_name: table_name.to_string(),
            table_key,
        })
    }
    pub async fn create_table(session: Arc<Session>, keyspace: &str, table_name: &str, _table_key: QDatabaseTableRoutingKey) -> anyhow::Result<()> {
        create_table_if_not_exists(
                &session,
                keyspace,
                table_name,
                &format!(
                    "CREATE TABLE IF NOT EXISTS {}.{} (
                    obj_id BIGINT,
                    value BIGINT,
                    PRIMARY KEY ((obj_id))
                )",
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
impl ScyllaStandardPreparedTableStatements for ScyllaU64ToU64TablePreparedStatements {
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

impl ScyllaU64ToU64TablePreparedStatements {
    pub async fn delete_many_object_ids(&self, session: &Session, ids: &[u64]) -> anyhow::Result<()> {
        for &id in ids {
            session.execute_unpaged(&self.delete_1_prepared, (u64_to_i64_exact(id),)).await?;
        }
        Ok(())
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
