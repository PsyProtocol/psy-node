use std::sync::Arc;

use async_trait::async_trait;

use parth_core::data::db::table::QDatabaseTableRoutingKey;
use scylla::{client::session::Session, statement::prepared::PreparedStatement};

use crate::{table_creator::create_table_if_not_exists, tables::traits::ScyllaStandardPreparedTableStatements};

#[derive(Clone)]
pub struct ScyllaIMTNextAppendIndexPreparedStatements {
    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,

    pub insert_prepared: Arc<PreparedStatement>,
    pub delete_prepared: Arc<PreparedStatement>,
    pub select_prepared: Arc<PreparedStatement>,
}

impl ScyllaIMTNextAppendIndexPreparedStatements {
    pub async fn new_create_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        Self::create_table(&session, keyspace, table_name).await?;
        Self::new_from_session(session, keyspace, table_name, table_key).await
    }

    pub async fn create_table(session: &Arc<Session>, keyspace: &str, table_name: &str) -> anyhow::Result<()> {
        create_table_if_not_exists(
            session,
            keyspace,
            table_name,
            &format!(
            r#"CREATE TABLE IF NOT EXISTS {}.{} (
                tree_id BIGINT,
                tree_sub_id BIGINT,
                next_append_index BIGINT,
                PRIMARY KEY ((tree_id, tree_sub_id))
            )"#,
            keyspace, table_name
        ),
        )
        .await?;
        session.await_schema_agreement().await?;
        tracing::info!("Created IMT next append index table: {}.{}", keyspace, table_name);
        Ok(())
    }

    pub async fn new_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        let insert_cql = format!(
            r#"INSERT INTO {}.{} (tree_id, tree_sub_id, next_append_index) VALUES (?, ?, ?)"#,
            keyspace, table_name
        );
        let select_cql = format!(
            r#"SELECT next_append_index FROM {}.{} WHERE tree_id = ? AND tree_sub_id = ? LIMIT 1"#,
            keyspace, table_name
        );

        tracing::info!("Preparing IMT next append index statements: {}.{}", keyspace, table_name);
        let insert_prepared = session.prepare(insert_cql).await?;
        let select_prepared = session.prepare(select_cql).await?;
        let delete_prepared = session.prepare(format!(
            r#"DELETE FROM {}.{} WHERE tree_id = ? AND tree_sub_id = ?"#,
            keyspace, table_name
        )).await?;
        tracing::info!("Prepared IMT next append index statements: {}.{}", keyspace, table_name);

        Ok(Self {
            keyspace: keyspace.to_string(),
            table_name: table_name.to_string(),
            table_key,
            insert_prepared: Arc::new(insert_prepared),
            delete_prepared: Arc::new(delete_prepared),
            select_prepared: Arc::new(select_prepared),
        })
    }

    pub async fn delete_many(&self, session: &Session, keys: &[(i64, i64)]) -> anyhow::Result<()> {
        for &key in keys {
            session.execute_unpaged(&self.delete_prepared, key).await?;
        }
        Ok(())
    }

    pub async fn insert(
        &self,
        session: &Session,
        tree_id: i64,
        tree_sub_id: i64,
        next_append_index: i64,
    ) -> anyhow::Result<()> {
        session
            .execute_unpaged(
                &self.insert_prepared,
                (tree_id, tree_sub_id, next_append_index),
            )
            .await?;
        Ok(())
    }

    pub async fn select(
        &self,
        session: &Session,
        tree_id: i64,
        tree_sub_id: i64,
    ) -> anyhow::Result<Option<i64>> {
        let result = session
            .execute_unpaged(&self.select_prepared, (tree_id, tree_sub_id))
            .await?;

        let rows = result.into_rows_result()?;
        match rows.maybe_first_row::<(i64,)>()? {
            Some((idx,)) => Ok(Some(idx)),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl ScyllaStandardPreparedTableStatements for ScyllaIMTNextAppendIndexPreparedStatements {
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
