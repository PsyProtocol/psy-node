use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use futures::{future::join_all, stream, StreamExt, TryStreamExt};
use parth_core::{
    data::db::{hash_id_u64::read_hash256_refs_and_i64s_from_buffer, table::QDatabaseTableRoutingKey},
    protocol::core_types::Q256BitHash,
};
use psy_serialize::PsySerializeCanonicalAsyncSafe;
use scylla::{
    client::session::Session,
    statement::{batch::Batch, prepared::PreparedStatement, Statement},
};

// Assuming these utility and constant modules exist in your project
use crate::{
    constants::INSERT_HASH_ID_TO_U64_VALUE_BATCH_SIZE,
    tables::traits::ScyllaStandardPreparedTableStatements,
    utils::{generate_batch_pre_prepared_statements, i64_to_u64_exact, u64_to_i64_exact},
};

pub trait DatabaseHashId: PsySerializeCanonicalAsyncSafe + Q256BitHash + Sized {
    fn dhi_from_vec_bytes(data: Vec<u8>) -> anyhow::Result<Self> {
        if data.len() != 32 {
            anyhow::bail!("expected 32 bytes for a hash, got {}", data.len());
        }
        let hash_bytes: [u8; 32] = data.try_into().unwrap();
        Ok(Self::from_owned_32bytes(hash_bytes))
    }
    fn dhi_to_hash_bytes(&self) -> [u8; 32] {
        self.into_owned_32bytes()
    }
}

impl<T: PsySerializeCanonicalAsyncSafe + Q256BitHash + Sized> DatabaseHashId for T {}

#[derive(Clone)]
pub struct ScyllaHashToManyIdsTablePreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,

    pub select_values_statement: Statement,
    pub select_values_prepared: Arc<PreparedStatement>,

    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
}

impl ScyllaHashToManyIdsTablePreparedStatements {
    pub async fn new_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(format!("INSERT INTO {}.{} (hash_id, value_u64) VALUES (?, ?)", keyspace, table_name));
        let insert_1_prepared = session.prepare(insert_1_statement.clone()).await?;

        // --- FIX IMPLEMENTED HERE: Using >= for robust pagination ---
        let select_values_statement = Statement::new(format!(
            "SELECT value_u64 FROM {}.{} WHERE hash_id = ? AND value_u64 >= ? LIMIT ?",
            keyspace, table_name
        ));
        let select_values_prepared = session.prepare(select_values_statement.clone()).await?;

        Ok(Self {
            insert_1_statement: insert_1_statement,
            insert_1_prepared: Arc::new(insert_1_prepared),
            select_values_statement,
            select_values_prepared: Arc::new(select_values_prepared),

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
                    hash_id BLOB,
                    value_u64 BIGINT,
                    PRIMARY KEY (hash_id, value_u64)
                ) WITH CLUSTERING ORDER BY (value_u64 ASC)",
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
impl ScyllaStandardPreparedTableStatements for ScyllaHashToManyIdsTablePreparedStatements {
    async fn create_table_standard(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::new_create_from_session(session, keyspace, table_name, table_key).await
    }
}

impl ScyllaHashToManyIdsTablePreparedStatements {
    pub async fn insert_one_hash_to_u64<Hash: DatabaseHashId>(&self, session: &Session, hash_id: Hash, value: u64) -> anyhow::Result<()> {
        let hash_bytes = hash_id.dhi_to_hash_bytes().to_vec();
        session
            .execute_unpaged(&self.insert_1_prepared, (hash_bytes, u64_to_i64_exact(value)))
            .await?;
        Ok(())
    }

    pub async fn insert_many_hash_to_u64s<Hash: DatabaseHashId>(&self, session: &Session, rows: &[(Hash, u64)]) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        // Note: The tuple should be ([u8; 32], i64) if using the array directly,
        // but Scylla binds BLOBs as Vec<u8> generally, though arrays can sometimes
        // work. Sticking to Vec<u8> for the hash for consistency with Scylla's
        // binding logic for BLOB.
        let mut value_list: Vec<Vec<(Vec<u8>, i64)>> = Vec::new();

        for chunk in rows.chunks(INSERT_HASH_ID_TO_U64_VALUE_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| Ok((n.0.dhi_to_hash_bytes().to_vec(), u64_to_i64_exact(n.1))))
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
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

    pub async fn set_hash_256_to_u64_pairs_from_fast_serialized_data(&self, session: &Session, data: &[u8]) -> anyhow::Result<()> {
        if data.len() % 40 != 0 {
            anyhow::bail!(
                "expected input bytes to be a multiple of 40 (hash + id), got a buffer of length {}",
                data.len()
            );
        }
        let count = data.len() / 40;
        if count == 0 {
            return Ok(());
        }
        const BATCH_SIZE: usize = 256;
        let count_remainder = count % BATCH_SIZE;
        let num_of_batches = count / BATCH_SIZE + if count_remainder == 0 { 0 } else { 1 };

        let (full_batch, partial_batch) = {
            if count <= BATCH_SIZE || count_remainder == 0 {
                let full = Arc::new(generate_batch_pre_prepared_statements(&self.insert_1_prepared, count.min(BATCH_SIZE)));
                let partial = full.clone();
                (full, partial)
            } else {
                let full = Arc::new(generate_batch_pre_prepared_statements(&self.insert_1_prepared, BATCH_SIZE));
                let partial = Arc::new(generate_batch_pre_prepared_statements(&self.insert_1_prepared, count_remainder));
                (full, partial)
            }
        };
        const CONCURRENCY_LIMIT: usize = 128;

        stream::iter(0..num_of_batches)
            .map(anyhow::Ok)
            .try_for_each_concurrent(CONCURRENCY_LIMIT, |ind| {
                let batch_prepared = if ind == (num_of_batches - 1) {
                    partial_batch.clone()
                } else {
                    full_batch.clone()
                };
                let group_size = if ind == num_of_batches - 1 { count_remainder } else { BATCH_SIZE };
                let start_index = ind * BATCH_SIZE * 40;
                let end_index = start_index + group_size * 40;
                async move {
                    let rows = read_hash256_refs_and_i64s_from_buffer(&data[start_index..end_index])?;

                    session.batch(&batch_prepared, rows).await.context("Batch insert failed")?;

                    Ok(())
                }
            })
            .await?;

        Ok(())
    }

    /// Selects up to `count` user IDs associated with the given hash, starting
    /// from `start_u64_value`.
    ///
    /// # Pagination
    /// - To start, set `start_u64_value` to 0.
    /// - For subsequent pages, set `start_u64_value` to the largest `u64` value
    ///   returned in the previous result **plus one**. (This is required to
    ///   skip the last returned element and continue to the next one).
    pub async fn select_value_u64_ids_for_hash<Hash: DatabaseHashId>(
        &self,
        session: &Session,
        hash: Hash,
        count: i32,
        start_u64_value: u64, // The ID to start the query from (inclusive)
    ) -> anyhow::Result<Vec<u64>> {
        let hash_bytes = hash.dhi_to_hash_bytes().to_vec();

        // start_u64_value is bound to value_u64 >= ?
        let start_u64_i64 = u64_to_i64_exact(start_u64_value);

        let res = session
            .execute_unpaged(&self.select_values_prepared, (hash_bytes, start_u64_i64, count))
            .await?;

        let rows_result = res.into_rows_result()?;

        // Rows contain tuples of (i64,) for the selected value_u64
        let rows: Vec<u64> = rows_result
            .rows::<(i64,)>()?
            .map(|x| x.map_err(|e| anyhow::anyhow!("{:?}", e)))
            .collect::<anyhow::Result<Vec<_>>>()?
            .iter()
            .map(|x| i64_to_u64_exact(x.0))
            .collect();

        Ok(rows)
    }
}
