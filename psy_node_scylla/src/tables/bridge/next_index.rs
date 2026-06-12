use std::sync::Arc;

use async_trait::async_trait;
use parth_core::data::db::table::QDatabaseTableRoutingKey;
use scylla::{client::session::Session, statement::prepared::PreparedStatement};

use crate::tables::traits::ScyllaStandardPreparedTableStatements;

/// Per-chain next deposit append index table.
///
/// Schema:
/// ```sql
/// CREATE TABLE IF NOT EXISTS {keyspace}.{table_name} (
///     chain_id BIGINT,
///     next_index BIGINT,
///     PRIMARY KEY (chain_id)
/// )
/// ```
#[derive(Clone)]
pub struct ScyllaBridgeDepositNextIndexPreparedStatements {
    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,

    pub insert_prepared: Arc<PreparedStatement>,
    pub select_prepared: Arc<PreparedStatement>,
}

impl ScyllaBridgeDepositNextIndexPreparedStatements {
    pub async fn new_create_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::create_table(&session, keyspace, table_name).await?;
        Self::new_from_session(session, keyspace, table_name, table_key).await
    }

    pub async fn create_table(session: &Session, keyspace: &str, table_name: &str) -> anyhow::Result<()> {
        let create_statement = format!(
            "CREATE TABLE IF NOT EXISTS {keyspace}.{table_name} (
                chain_id BIGINT,
                next_index BIGINT,
                PRIMARY KEY (chain_id)
            )"
        );
        session.query_unpaged(create_statement, &[]).await?;
        Ok(())
    }

    pub async fn new_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        let insert_stmt = format!(
            "INSERT INTO {keyspace}.{table_name} (chain_id, next_index) VALUES (?, ?)"
        );
        let select_stmt = format!(
            "SELECT next_index FROM {keyspace}.{table_name} WHERE chain_id = ? LIMIT 1"
        );
        let insert_prepared = session.prepare(insert_stmt).await?;
        let select_prepared = session.prepare(select_stmt).await?;
        Ok(Self {
            keyspace: keyspace.to_string(),
            table_name: table_name.to_string(),
            table_key,
            insert_prepared: Arc::new(insert_prepared),
            select_prepared: Arc::new(select_prepared),
        })
    }

    pub async fn set_next_index(&self, session: &Session, chain_id: i64, next_index: i64) -> anyhow::Result<()> {
        session
            .execute_unpaged(&self.insert_prepared, (chain_id, next_index))
            .await?;
        Ok(())
    }

    pub async fn get_next_index(&self, session: &Session, chain_id: i64) -> anyhow::Result<Option<i64>> {
        let result = session
            .execute_unpaged(&self.select_prepared, (chain_id,))
            .await?;
        let rows = result.into_rows_result()?;
        match rows.maybe_first_row::<(i64,)>()? {
            Some((v,)) => Ok(Some(v)),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl ScyllaStandardPreparedTableStatements for ScyllaBridgeDepositNextIndexPreparedStatements {
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

