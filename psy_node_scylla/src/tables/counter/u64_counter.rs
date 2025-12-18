use std::sync::Arc;
use async_trait::async_trait;
use futures::future::join_all;
use parth_core::data::db::table::QDatabaseTableRoutingKey;
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Statement},
};
use crate::{
    constants::SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE, table_creator::create_table_if_not_exists, tables::traits::ScyllaNoTabletPreparedTableStatements, utils::{i64_to_u64_exact, u64_to_i64_exact}
};

#[derive(Clone)]
pub struct ScyllaU64ToU64CounterTablePreparedStatements {
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

const fn is_u64_safe_for_counter(value: u64) -> bool {
    value <= i64::MAX as u64
}

impl ScyllaU64ToU64CounterTablePreparedStatements {
    pub async fn new_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {

        let select_value_1_statement = Statement::new(format!("SELECT value FROM {}.{} WHERE obj_id = ?", keyspace, table_name));
        let select_value_1_prepared = session.prepare(select_value_1_statement.clone()).await?;

        let select_all_statement = Statement::new(format!("SELECT obj_id, value FROM {}.{}", keyspace, table_name));
        let select_all_prepared = session.prepare(select_all_statement.clone()).await?;

        let update_if_exists_statement = Statement::new(format!("UPDATE {}.{} SET value = ? WHERE obj_id = ? IF value = ?", keyspace, table_name));
        let update_if_exists_prepared = session.prepare(update_if_exists_statement.clone()).await?;

        let insert_if_not_exists_statement = Statement::new(format!("INSERT INTO {}.{} (obj_id, value) VALUES (?, ?) IF NOT EXISTS", keyspace, table_name));
        let insert_if_not_exists_prepared = session.prepare(insert_if_not_exists_statement.clone()).await?;

        Ok(Self {
            select_value_1_statement: select_value_1_statement,
            select_value_1_prepared: Arc::new(select_value_1_prepared),
            select_all_statement: select_all_statement,
            select_all_prepared: Arc::new(select_all_prepared),
            update_if_exists_statement: update_if_exists_statement,
            update_if_exists_prepared: Arc::new(update_if_exists_prepared),
            insert_if_not_exists_statement,
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
        no_tablet_keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::create_table(session.clone(), no_tablet_keyspace, table_name, table_key).await?;
        Self::new_from_session(session, no_tablet_keyspace, table_name, table_key).await
    }
}
#[async_trait]
impl ScyllaNoTabletPreparedTableStatements for ScyllaU64ToU64CounterTablePreparedStatements {
    async fn create_table_no_tablet(
        session: Arc<Session>,
        no_tablet_keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::new_create_from_session(session, no_tablet_keyspace, table_name, table_key).await
    }
}

impl ScyllaU64ToU64CounterTablePreparedStatements {
    pub async fn atomic_increment(&self, session: &Session, obj_id: u64, amount: u64) -> anyhow::Result<u64> {
        const MAX_RETRIES: usize = 10;
        for _ in 0..MAX_RETRIES {
            let old_opt = self.select_one_single(session, obj_id).await?;
            match old_opt {
                Some(old_u64) => {
                    let new_u64 = old_u64.checked_add(amount)
                        .ok_or_else(|| anyhow::anyhow!("Overflow when adding {} to {}", amount, old_u64))?;
                    if !is_u64_safe_for_counter(new_u64) {
                        return Err(anyhow::anyhow!("New value {} exceeds i64::MAX", new_u64));
                    }
                    let old_i64 = u64_to_i64_exact(old_u64);
                    let new_i64 = u64_to_i64_exact(new_u64);
                    let res = session
                        .execute_unpaged(&self.update_if_exists_prepared, (new_i64, u64_to_i64_exact(obj_id), old_i64))
                        .await?;
                    let rows = res.into_rows_result()?;
                    if let Some(row) = rows.maybe_first_row::<(bool,i64)>()? {
                        if row.0 {
                            return Ok(new_u64);
                        }
                    }
                }
                None => {
                    let new_u64 = amount;
                    if !is_u64_safe_for_counter(new_u64) {
                        return Err(anyhow::anyhow!("New value {} exceeds i64::MAX", new_u64));
                    }
                    let new_i64 = u64_to_i64_exact(new_u64);
                    let res = session
                        .execute_unpaged(&self.insert_if_not_exists_prepared, (u64_to_i64_exact(obj_id), new_i64))
                        .await?;
                    let rows = res.into_rows_result()?;
                    if let Some(row) = rows.maybe_first_row::<(bool,Option<i64>, Option<i64>)>()? {
                        if row.0 {
                            return Ok(new_u64);
                        }
                    }
                }
            }
        }
        Err(anyhow::anyhow!("Failed to apply increment after {} retries", MAX_RETRIES))
    }
    pub async fn select_one_single(&self, session: &Session, obj_id: u64) -> anyhow::Result<Option<u64>> {
        let res = session
            .execute_unpaged(&self.select_value_1_prepared, (u64_to_i64_exact(obj_id),))
            .await?;
        let current_value_i64 = res.into_rows_result()?.maybe_first_row::<(Option<i64>,)>()?.and_then(|(val,)| val);
        match current_value_i64 {
            Some(val) if val >= 0 => Ok(Some(i64_to_u64_exact(val))),
            Some(_) => Err(anyhow::anyhow!("Negative value encountered in counter")),
            None => Ok(None),
        }
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
                                Some(val) if val >= 0 => Ok(Some(i64_to_u64_exact(val))),
                                Some(_) => Err(anyhow::anyhow!("Negative value encountered in counter")),
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