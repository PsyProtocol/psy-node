use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use futures::future::join_all;
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::{
        db::table::QDatabaseTableRoutingKey,
        hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey},
    },
    protocol::core_types::QHashBase,
};
use scylla::{
    client::session::Session,
    statement::{batch::Batch, prepared::PreparedStatement, Statement},
};

use crate::{
    tables::traits::ScyllaStandardPreparedTableStatements,
    utils::{convert_checkpoint_id_to_i64, u64_to_i64_exact, u8_to_i8_exact},
};


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
    pub async fn new_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(&format!(
            "INSERT INTO {}.{} (tree_id, tree_sub_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?, ?)",
            keyspace, table_name
        ));
        let insert_1_prepared = session.prepare(insert_1_statement.clone()).await?;
        let select_1_statement = Statement::new(&format!(
            "SELECT value FROM {}.{} WHERE tree_id = ? AND tree_sub_id = ? AND level = ? AND node_index = ? AND checkpoint_id <= ? LIMIT 1",
            keyspace, table_name
        ));
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
impl ScyllaStandardPreparedTableStatements for ScyllaDoubleMerkleNodesPreparedStatements {
    async fn create_table_standard(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::new_create_from_session(session, keyspace, table_name, table_key).await
    }
}

impl ScyllaDoubleMerkleNodesPreparedStatements {

    pub async fn set_double_id_merkle_nodes_batch_internal<Hash: QHashBase>(
        &self,
        session: &Session,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        nodes: Vec<SimpleMerkleNode<Hash>>,
    ) -> anyhow::Result<()> {
        const BATCH_SIZE: usize = 256; // Safe batch size to avoid payload limits
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let mut value_list: Vec<Vec<(i64, i64, i8, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in nodes.chunks(BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(tree_id), u64_to_i64_exact(tree_sub_id), u8_to_i8_exact(n.key.level), u64_to_i64_exact(n.key.index), checkpoint_id as i64, n.value.to_bytes()?))
                })
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }
    pub async fn select_double_id_merkle_node_max_checkpoint_internal<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>(&self, session: &Session, checkpoint_id: u64, tree_id: u64, tree_height: u8, tree_secondary_id: u64, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash> {
        let res = session.execute_unpaged(&self.select_1_prepared, (u64_to_i64_exact(tree_id), u64_to_i64_exact(tree_secondary_id), u8_to_i8_exact(key.level), u64_to_i64_exact(key.index), convert_checkpoint_id_to_i64(checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => if row.0.len() == Hash::get_fixed_size() {
                Ok(Hash::from_bytes(&row.0)?)
            } else {
                Ok(Hasher::get_zero_hash((tree_height - key.level) as usize))
            },
            None => Ok(Hasher::get_zero_hash((tree_height - key.level) as usize)),
        }
    }


    pub async fn select_many_double_id_merkle_nodes_max_checkpoint_internal<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>(
        &self,
        session: &Session,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        const CONCURRENT_LIMIT: usize = 512; // Batch concurrent queries
        let mut results = Vec::with_capacity(keys.len());
        for chunk in keys.chunks(CONCURRENT_LIMIT) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let prep = self.select_1_prepared.clone();
                    let tree_id_i64 = u64_to_i64_exact(tree_id);
                    let tree_sub_id_i64 = u64_to_i64_exact(tree_sub_id);
                    let level_i8 = u8_to_i8_exact(key.level);
                    let index_i64 = u64_to_i64_exact(key.index);
                    let max_cp_i64 = if max_checkpoint_id > i64::MAX as u64 {
                        i64::MAX
                    } else {
                        max_checkpoint_id as i64
                    };
                    async move {
                        let res = session.execute_unpaged(&prep, (tree_id_i64, tree_sub_id_i64, level_i8, index_i64, max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                            Hash::from_bytes(&row.0)
                        } else {
                            // Assume reverse_level = level for simplicity; adjust if tree height known
                            Ok(Hasher::get_zero_hash((tree_height-key.level) as usize))
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
    pub async fn insert_double_id_merkle_node_internal(&self, session: &Session, checkpoint_id: u64, tree_id: u64, tree_secondary_id: u64, key: SimpleMerkleNodeKey, value: &[u8]) -> anyhow::Result<()> {
        session.execute_unpaged(&self.insert_1_prepared, (u64_to_i64_exact(tree_id), u64_to_i64_exact(tree_secondary_id), u8_to_i8_exact(key.level), u64_to_i64_exact(key.index), convert_checkpoint_id_to_i64(checkpoint_id), value)).await?;
        Ok(())
    }
}