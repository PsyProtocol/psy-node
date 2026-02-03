use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use futures::future::join_all;
use parth_core::data::db::table::QDatabaseTableRoutingKey;
use scylla::{
    client::session::Session,
    statement::{batch::Batch, prepared::PreparedStatement, Statement},
};
use uuid::Uuid;

use crate::{
    constants::{INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE, SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE}, table_creator::create_table_if_not_exists, tables::traits::ScyllaStandardPreparedTableStatements, utils::{i64_to_u64_exact, u64_to_i64_exact}
};

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
        create_table_if_not_exists(
                &session,
                keyspace,
                table_name,
                &format!(
                    "CREATE TABLE IF NOT EXISTS {}.{} (
                    obj_id UUID,
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

    async fn prepare_only_standard(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::new_from_session(session, keyspace, table_name, table_key).await
    }
}