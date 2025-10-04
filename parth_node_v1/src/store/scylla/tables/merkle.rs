use std::sync::Arc;

use parth_core::data::db::table::QDatabaseTableRoutingKey;
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Statement},
};

#[derive(Clone)]
pub struct ScyllaMerkleNodesPreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,
    pub select_1_statement: Statement,
    pub select_1_prepared: Arc<PreparedStatement>,
    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
}

impl ScyllaMerkleNodesPreparedStatements {
    pub async fn new_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(&format!("INSERT INTO {}.{} (tree_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?)", keyspace, table_name));
        let insert_prepared = session.prepare(insert_1_statement.clone()).await?;
        let select_1_statement =
            Statement::new(&format!("SELECT value FROM {}.{} WHERE tree_id = ? AND level = ? AND node_index = ? AND checkpoint_id <= ? LIMIT 1", keyspace, table_name));
        let select_1_prepared = session.prepare(select_1_statement.clone()).await?;

        Ok(Self {
            insert_1_prepared: Arc::new(insert_prepared),
            select_1_prepared: Arc::new(select_1_prepared),
            insert_1_statement: insert_1_statement,
            select_1_statement: select_1_statement,
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
                    tree_id BIGINT,
                    level TINYINT,
                    node_index BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((tree_id), level, node_index, checkpoint_id)
                ) WITH CLUSTERING ORDER BY (level ASC, node_index ASC, checkpoint_id DESC)",
                    keyspace, table_name
                ),
                &[],
            )
            .await?;
        session.await_schema_agreement().await?;
        Ok(())
    }
    pub async fn new_create_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        Self::create_table(session.clone(), keyspace, table_name, table_key).await?;
        Self::new_from_session(session, keyspace, table_name, table_key).await
    }
}

#[derive(Clone)]
pub struct ScyllaDoubleMerkleNodesPreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,
    pub select_1_statement: Statement,
    pub select_1_prepared: Arc<PreparedStatement>,
    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
}

impl ScyllaDoubleMerkleNodesPreparedStatements {
    pub async fn new_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(
            &format!("INSERT INTO {}.{} (tree_id, tree_sub_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?, ?)", keyspace, table_name),
        );
        let insert_1_prepared = session.prepare(insert_1_statement.clone()).await?;
        let select_1_statement = Statement::new(&format!("SELECT value FROM {}.{} WHERE tree_id = ? AND tree_sub_id = ? AND level = ? AND node_index = ? AND checkpoint_id <= ? LIMIT 1", keyspace, table_name));
        let select_1_prepared = session.prepare(select_1_statement.clone()).await?;

        Ok(Self {
            insert_1_statement,
            insert_1_prepared: Arc::new(insert_1_prepared),
            select_1_statement,
            select_1_prepared: Arc::new(select_1_prepared),
            table_key,
            keyspace: keyspace.to_string(),
            table_name: table_name.to_string(),
        })
    }
    pub async fn create_table(session: Arc<Session>, keyspace: &str, table_name: &str, _table_key: QDatabaseTableRoutingKey) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {}.{} (
                    tree_id BIGINT,
                    tree_sub_id BIGINT,
                    level TINYINT,
                    node_index BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((tree_id, tree_sub_id), level, node_index, checkpoint_id)
                ) WITH CLUSTERING ORDER BY (level ASC, node_index ASC, checkpoint_id DESC)",
                    keyspace, table_name
                ),
                &[],
            )
            .await?;
        session.await_schema_agreement().await?;
        Ok(())
    }
    pub async fn new_create_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        Self::create_table(session.clone(), keyspace, table_name, table_key).await?;
        Self::new_from_session(session, keyspace, table_name, table_key).await
    }
}
