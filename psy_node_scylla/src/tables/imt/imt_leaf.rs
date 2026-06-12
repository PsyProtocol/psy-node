use std::sync::Arc;

use async_trait::async_trait;
use parth_core::data::db::table::QDatabaseTableRoutingKey;
use scylla::{client::session::Session, statement::prepared::PreparedStatement};

use crate::{table_creator::create_table_if_not_exists, tables::traits::ScyllaStandardPreparedTableStatements};

/// ScyllaDB prepared statements for the contract state IMT leaf preimage table.
///
/// Schema:
/// ```sql
/// CREATE TABLE IF NOT EXISTS {keyspace}.{table_name} (
///     tree_id BIGINT,          -- user_id
///     tree_sub_id BIGINT,      -- contract_id
///     leaf_index BIGINT,       -- append position in tree
///     checkpoint_id BIGINT,    -- version
///     leaf_hash BLOB,          -- 32 bytes, computed hash
///     leaf_key BLOB,           -- 32 bytes, storage key
///     leaf_value BLOB,         -- 32 bytes, storage value
///     next_key BLOB,           -- 32 bytes, successor key
///     next_index BIGINT,       -- successor leaf index
///     PRIMARY KEY ((tree_id, tree_sub_id, leaf_index), checkpoint_id)
/// ) WITH CLUSTERING ORDER BY (checkpoint_id DESC)
/// ```
#[derive(Clone)]
pub struct ScyllaIMTLeafPreparedStatements {
    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,

    pub insert_prepared: Arc<PreparedStatement>,
    pub select_prepared: Arc<PreparedStatement>,
}

impl ScyllaIMTLeafPreparedStatements {
    pub async fn new_create_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        Self::create_table(&session, keyspace, table_name).await?;
        Self::new_from_session(session, keyspace, table_name, table_key).await
    }

    pub async fn create_table(session: &Session, keyspace: &str, table_name: &str) -> anyhow::Result<()> {
        create_table_if_not_exists(
            session,
            keyspace,
            table_name,
            &format!(
                "CREATE TABLE IF NOT EXISTS {keyspace}.{table_name} (
                tree_id BIGINT,
                tree_sub_id BIGINT,
                leaf_index BIGINT,
                checkpoint_id BIGINT,
                leaf_hash BLOB,
                leaf_key BLOB,
                leaf_value BLOB,
                next_key BLOB,
                next_index BIGINT,
                PRIMARY KEY ((tree_id, tree_sub_id, leaf_index), checkpoint_id)
            ) WITH CLUSTERING ORDER BY (checkpoint_id DESC)
                AND compaction = {{
                    'class': 'LeveledCompactionStrategy',
                    'sstable_size_in_mb': 160
                }}
                AND compression = {{
                    'sstable_compression': 'LZ4Compressor',
                    'chunk_length_in_kb': 4
                }}
                AND bloom_filter_fp_chance = 0.01
                AND caching = {{'keys': 'ALL', 'rows_per_partition': 4}}
                AND gc_grace_seconds = 864000"
            ),
        )
        .await?;
        session.await_schema_agreement().await?;
        Ok(())
    }

    pub async fn new_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        let insert_stmt = format!(
            "INSERT INTO {keyspace}.{table_name} \
             (tree_id, tree_sub_id, leaf_index, checkpoint_id, leaf_hash, leaf_key, leaf_value, next_key, next_index) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        );
        let select_stmt = format!(
            "SELECT leaf_hash, leaf_key, leaf_value, next_key, next_index \
             FROM {keyspace}.{table_name} \
             WHERE tree_id = ? AND tree_sub_id = ? AND leaf_index = ? AND checkpoint_id <= ? \
             LIMIT 1"
        );

        tracing::info!("Preparing IMT leaf statements: {}.{}", keyspace, table_name);
        let insert_prepared = session.prepare(insert_stmt).await?;
        let select_prepared = session.prepare(select_stmt).await?;
        tracing::info!("Prepared IMT leaf statements: {}.{}", keyspace, table_name);

        Ok(Self {
            keyspace: keyspace.to_string(),
            table_name: table_name.to_string(),
            table_key,
            insert_prepared: Arc::new(insert_prepared),
            select_prepared: Arc::new(select_prepared),
        })
    }

    /// Insert a single IMT leaf preimage.
    pub async fn insert_leaf(
        &self,
        session: &Session,
        tree_id: i64,
        tree_sub_id: i64,
        leaf_index: i64,
        checkpoint_id: i64,
        leaf_hash: &[u8],
        leaf_key: &[u8],
        leaf_value: &[u8],
        next_key: &[u8],
        next_index: i64,
    ) -> anyhow::Result<()> {
        session
            .execute_unpaged(
                &self.insert_prepared,
                (
                    tree_id,
                    tree_sub_id,
                    leaf_index,
                    checkpoint_id,
                    leaf_hash,
                    leaf_key,
                    leaf_value,
                    next_key,
                    next_index,
                ),
            )
            .await?;
        Ok(())
    }

    /// Select the latest IMT leaf preimage at or before the given checkpoint.
    pub async fn select_leaf(
        &self,
        session: &Session,
        tree_id: i64,
        tree_sub_id: i64,
        leaf_index: i64,
        max_checkpoint_id: i64,
    ) -> anyhow::Result<Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64)>> {
        let result = session
            .execute_unpaged(&self.select_prepared, (tree_id, tree_sub_id, leaf_index, max_checkpoint_id))
            .await?;

        let rows = result.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64)>()? {
            Some(row) => Ok(Some(row)),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl ScyllaStandardPreparedTableStatements for ScyllaIMTLeafPreparedStatements {
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
