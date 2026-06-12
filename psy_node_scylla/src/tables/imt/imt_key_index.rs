use std::sync::Arc;

use async_trait::async_trait;
use parth_core::data::db::table::QDatabaseTableRoutingKey;
use scylla::{client::session::Session, statement::prepared::PreparedStatement};

use crate::{table_creator::create_table_if_not_exists, tables::traits::ScyllaStandardPreparedTableStatements};

/// ScyllaDB prepared statements for the contract state IMT key-to-leaf index
/// table.
///
/// This table maps storage keys to leaf indices in the IMT, enabling:
/// - Exact key lookups (membership checks)
/// - Predecessor lookups (for non-membership proofs)
///
/// Keys are stored in comparison-compatible encoding (MSL-first, each limb
/// big-endian) so ScyllaDB's byte-by-byte lexicographic comparison matches
/// numerical ordering.
///
/// Schema:
/// ```sql
/// CREATE TABLE IF NOT EXISTS {keyspace}.{table_name} (
///     tree_id BIGINT,          -- user_id
///     tree_sub_id BIGINT,      -- contract_id
///     key_bucket SMALLINT,     -- first 2 bytes of sort-encoded key (65536 buckets)
///     encoded_key BLOB,        -- 32 bytes, comparison-compatible encoding (MSL-first)
///     leaf_key BLOB,           -- 32 bytes, original key (for returning to caller)
///     birth_checkpoint BIGINT, -- checkpoint when this key was inserted
///     leaf_index BIGINT,       -- leaf position in tree
///     PRIMARY KEY ((tree_id, tree_sub_id, key_bucket), encoded_key)
/// ) WITH CLUSTERING ORDER BY (encoded_key ASC)
/// ```
///
/// Note: encoded_key is used for proper lexicographic ordering (MSL-first),
/// while leaf_key is stored for returning to callers.
///
/// Not versioned: keys are never removed in an append-only IMT.
/// birth_checkpoint enables historical queries.
#[derive(Clone)]
pub struct ScyllaIMTKeyIndexPreparedStatements {
    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,

    pub insert_prepared: Arc<PreparedStatement>,
    pub select_exact_prepared: Arc<PreparedStatement>,
    pub select_predecessor_prepared: Arc<PreparedStatement>,
    pub select_predecessor_full_bucket_prepared: Arc<PreparedStatement>,
}

impl ScyllaIMTKeyIndexPreparedStatements {
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
                key_bucket SMALLINT,
                encoded_key BLOB,
                leaf_key BLOB,
                birth_checkpoint BIGINT,
                leaf_index BIGINT,
                PRIMARY KEY ((tree_id, tree_sub_id, key_bucket), encoded_key)
            ) WITH CLUSTERING ORDER BY (encoded_key ASC)
                AND compaction = {{
                    'class': 'LeveledCompactionStrategy',
                    'sstable_size_in_mb': 160
                }}
                AND compression = {{
                    'sstable_compression': 'LZ4Compressor'
                }}
                AND bloom_filter_fp_chance = 0.01
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
             (tree_id, tree_sub_id, key_bucket, encoded_key, leaf_key, birth_checkpoint, leaf_index) \
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        );
        let select_exact_stmt = format!(
            "SELECT leaf_index, birth_checkpoint \
             FROM {keyspace}.{table_name} \
             WHERE tree_id = ? AND tree_sub_id = ? AND key_bucket = ? AND encoded_key = ?"
        );
        // Predecessor: find largest key < target_encoded_key in the same bucket
        let select_predecessor_stmt = format!(
            "SELECT encoded_key, leaf_key, leaf_index, birth_checkpoint \
             FROM {keyspace}.{table_name} \
             WHERE tree_id = ? AND tree_sub_id = ? AND key_bucket = ? AND encoded_key < ? \
             ORDER BY encoded_key DESC \
             LIMIT 5"
        );
        // Predecessor across bucket boundary: get largest key in a bucket
        let select_predecessor_full_bucket_stmt = format!(
            "SELECT encoded_key, leaf_key, leaf_index, birth_checkpoint \
             FROM {keyspace}.{table_name} \
             WHERE tree_id = ? AND tree_sub_id = ? AND key_bucket = ? \
             ORDER BY encoded_key DESC \
             LIMIT 5"
        );

        tracing::info!("Preparing IMT key index statements: {}.{}", keyspace, table_name);
        let insert_prepared = session.prepare(insert_stmt).await?;
        let select_exact_prepared = session.prepare(select_exact_stmt).await?;
        let select_predecessor_prepared = session.prepare(select_predecessor_stmt).await?;
        let select_predecessor_full_bucket_prepared = session.prepare(select_predecessor_full_bucket_stmt).await?;
        tracing::info!("Prepared IMT key index statements: {}.{}", keyspace, table_name);

        Ok(Self {
            keyspace: keyspace.to_string(),
            table_name: table_name.to_string(),
            table_key,
            insert_prepared: Arc::new(insert_prepared),
            select_exact_prepared: Arc::new(select_exact_prepared),
            select_predecessor_prepared: Arc::new(select_predecessor_prepared),
            select_predecessor_full_bucket_prepared: Arc::new(select_predecessor_full_bucket_prepared),
        })
    }

    /// Insert a key-to-leaf mapping.
    pub async fn insert_key(
        &self,
        session: &Session,
        tree_id: i64,
        tree_sub_id: i64,
        key_bucket: i16,
        encoded_key: &[u8],
        leaf_key: &[u8],
        birth_checkpoint: i64,
        leaf_index: i64,
    ) -> anyhow::Result<()> {
        session
            .execute_unpaged(
                &self.insert_prepared,
                (tree_id, tree_sub_id, key_bucket, encoded_key, leaf_key, birth_checkpoint, leaf_index),
            )
            .await?;
        Ok(())
    }

    /// Exact key lookup: find the leaf index for a specific key.
    pub async fn select_exact(
        &self,
        session: &Session,
        tree_id: i64,
        tree_sub_id: i64,
        key_bucket: i16,
        encoded_key: &[u8],
    ) -> anyhow::Result<Option<(i64, i64)>> {
        let result = session
            .execute_unpaged(&self.select_exact_prepared, (tree_id, tree_sub_id, key_bucket, encoded_key))
            .await?;

        let rows = result.into_rows_result()?;
        match rows.maybe_first_row::<(i64, i64)>()? {
            Some(row) => Ok(Some(row)),
            None => Ok(None),
        }
    }

    /// Find predecessor: largest key < target_encoded_key in the same bucket.
    /// Returns up to 5 candidates (caller filters by birth_checkpoint).
    /// Returns (encoded_key, leaf_key, leaf_index, birth_checkpoint).
    pub async fn select_predecessor(
        &self,
        session: &Session,
        tree_id: i64,
        tree_sub_id: i64,
        key_bucket: i16,
        target_encoded_key: &[u8],
    ) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>, i64, i64)>> {
        let result = session
            .execute_unpaged(&self.select_predecessor_prepared, (tree_id, tree_sub_id, key_bucket, target_encoded_key))
            .await?;

        let rows_result = result.into_rows_result()?;
        let results: Vec<(Vec<u8>, Vec<u8>, i64, i64)> = rows_result
            .rows::<(Vec<u8>, Vec<u8>, i64, i64)>()?
            .map(|x| x.map_err(|e| anyhow::anyhow!("{:?}", e)))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(results)
    }

    /// Find predecessor across bucket boundary: get largest key in a previous
    /// bucket.
    /// Returns (encoded_key, leaf_key, leaf_index, birth_checkpoint).
    pub async fn select_predecessor_full_bucket(
        &self,
        session: &Session,
        tree_id: i64,
        tree_sub_id: i64,
        key_bucket: i16,
    ) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>, i64, i64)>> {
        let result = session
            .execute_unpaged(&self.select_predecessor_full_bucket_prepared, (tree_id, tree_sub_id, key_bucket))
            .await?;

        let rows_result = result.into_rows_result()?;
        let results: Vec<(Vec<u8>, Vec<u8>, i64, i64)> = rows_result
            .rows::<(Vec<u8>, Vec<u8>, i64, i64)>()?
            .map(|x| x.map_err(|e| anyhow::anyhow!("{:?}", e)))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(results)
    }
}

#[async_trait]
impl ScyllaStandardPreparedTableStatements for ScyllaIMTKeyIndexPreparedStatements {
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
