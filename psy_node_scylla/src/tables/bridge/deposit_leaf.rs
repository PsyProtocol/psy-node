use std::sync::Arc;

use async_trait::async_trait;
use parth_core::data::db::table::QDatabaseTableRoutingKey;
use scylla::{client::session::Session, statement::prepared::PreparedStatement};

use crate::tables::traits::ScyllaStandardPreparedTableStatements;

/// Checkpointed deposit leaf table for bridge deposits.
///
/// This table stores deposit leaves in bytes-native form (no field conversion),
/// keyed by `(chain_id, deposit_index)` and versioned by `checkpoint_id`.
///
/// Schema:
/// ```sql
/// CREATE TABLE IF NOT EXISTS {keyspace}.{table_name} (
///     chain_id BIGINT,
///     deposit_index BIGINT,
///     checkpoint_id BIGINT,
///     leaf_hash BLOB,
///     PRIMARY KEY ((chain_id, deposit_index), checkpoint_id)
/// ) WITH CLUSTERING ORDER BY (checkpoint_id DESC)
/// ```
#[derive(Clone)]
pub struct ScyllaBridgeDepositLeafPreparedStatements {
    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,

    pub insert_prepared: Arc<PreparedStatement>,
    pub select_prepared: Arc<PreparedStatement>,
}

impl ScyllaBridgeDepositLeafPreparedStatements {
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
                deposit_index BIGINT,
                checkpoint_id BIGINT,
                leaf_hash BLOB,
                PRIMARY KEY ((chain_id, deposit_index), checkpoint_id)
            ) WITH CLUSTERING ORDER BY (checkpoint_id DESC)
                AND compaction = {{
                    'class': 'LeveledCompactionStrategy',
                    'sstable_size_in_mb': 160
                }}
                AND compression = {{
                    'sstable_compression': 'LZ4Compressor'
                }}
                AND bloom_filter_fp_chance = 0.01
                AND gc_grace_seconds = 864000"
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
            "INSERT INTO {keyspace}.{table_name} (chain_id, deposit_index, checkpoint_id, leaf_hash) VALUES (?, ?, ?, ?)"
        );
        let select_stmt = format!(
            "SELECT leaf_hash FROM {keyspace}.{table_name}
             WHERE chain_id = ? AND deposit_index = ? AND checkpoint_id <= ? LIMIT 1"
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

    pub async fn insert_leaf(
        &self,
        session: &Session,
        chain_id: i64,
        deposit_index: i64,
        checkpoint_id: i64,
        leaf_hash: &[u8],
    ) -> anyhow::Result<()> {
        session
            .execute_unpaged(
                &self.insert_prepared,
                (chain_id, deposit_index, checkpoint_id, leaf_hash),
            )
            .await?;
        Ok(())
    }

    pub async fn select_leaf_at_or_before_checkpoint(
        &self,
        session: &Session,
        chain_id: i64,
        deposit_index: i64,
        max_checkpoint_id: i64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let result = session
            .execute_unpaged(
                &self.select_prepared,
                (chain_id, deposit_index, max_checkpoint_id),
            )
            .await?;
        let rows = result.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some((hash,)) => Ok(Some(hash)),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl ScyllaStandardPreparedTableStatements for ScyllaBridgeDepositLeafPreparedStatements {
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

