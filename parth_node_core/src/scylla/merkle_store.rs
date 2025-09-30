use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use futures::future::join_all;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::{hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}, serializable::QPDSerializableFixed}};
use scylla::{client::session::{Session, SessionConfig}, statement::{batch::Batch, unprepared::Statement}};

use crate::data::hash::QPMerkleTreeStore;

pub struct ScyllaMerkleTreeStore<Hash: PartialEq + Copy + QPDSerializableFixed, Hasher: MerkleZeroHasher<Hash> + Send + Sync> {
    session: Arc<Session>,
    _hash_size: usize,
    // Cached prepared statements for efficiency
    insert_prep: scylla::statement::prepared::PreparedStatement,
    select_prep: scylla::statement::prepared::PreparedStatement,
    hhasher: std::marker::PhantomData<Hasher>,
    hhash: std::marker::PhantomData<Hash>,
}
impl<Hash: PartialEq + Copy + QPDSerializableFixed, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    ScyllaMerkleTreeStore<Hash, Hasher>
{
    pub async fn new(known_nodes: Vec<String>) -> anyhow::Result<Self> {
        let mut config = SessionConfig::new();
        config.add_known_nodes(&known_nodes);
        let session = Arc::new(Session::connect(config).await?);

        // Create keyspace and table if not exists
        session
            .query_unpaged(
                "CREATE KEYSPACE IF NOT EXISTS merkle_ks WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}",
                &[],
            )
            .await?;
        session.await_schema_agreement().await?;
        session.use_keyspace("merkle_ks", false).await?;
        session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS merkle_nodes (
                    tree_id BIGINT,
                    level TINYINT,
                    node_index BIGINT,
                    block_height BIGINT,
                    value BLOB,
                    PRIMARY KEY ((tree_id), level, node_index, block_height)
                ) WITH CLUSTERING ORDER BY (level ASC, node_index ASC, block_height DESC)",
                &[],
            ).await?;
        session.await_schema_agreement().await?;

        // Prepare statements
        let insert_stmt = Statement::new("INSERT INTO merkle_nodes (tree_id, level, node_index, block_height, value) VALUES (?, ?, ?, ?, ?)");
        let insert_prep = session.prepare(insert_stmt).await?;
        let select_stmt = Statement::new("SELECT value FROM merkle_nodes WHERE tree_id = ? AND level = ? AND node_index = ? AND block_height <= ? LIMIT 1");
        let select_prep = session.prepare(select_stmt).await?;

        Ok(Self {
            session,
            _hash_size: Hash::get_fixed_size(),
            insert_prep,
            select_prep,
            hhasher: std::marker::PhantomData,
            hhash: std::marker::PhantomData,
        })
    }
}

#[async_trait]
impl<Hash: PartialEq + Copy + QPDSerializableFixed + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    QPMerkleTreeStore<Hash, Hasher> for ScyllaMerkleTreeStore<Hash, Hasher>
{
    async fn set_tree_nodes(
        &self,
        block_height: u64,
        tree_id: u64,
        nodes: Vec<SimpleMerkleNode<Hash>>,
    ) -> anyhow::Result<()> {
        const BATCH_SIZE: usize = 500; // Safe batch size to avoid payload limits
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i8, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in nodes.chunks(BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(self.insert_prep.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    let value_bytes = n.value.to_bytes()?;
                    Ok((tree_id as i64, n.key.level as i8, n.key.index as i64, block_height as i64, value_bytes))
                })
                .collect::<anyhow::Result<_>>()?;
            batch_list.push(batch);
            value_list.push(values);
        }
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| self.session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }

    async fn get_tree_nodes(
        &self,
        max_block_height: u64,
        tree_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        const CONCURRENT_LIMIT: usize = 1000; // Batch concurrent queries
        let mut results = Vec::with_capacity(keys.len());
        for chunk in keys.chunks(CONCURRENT_LIMIT) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = self.session.clone();
                    let prep = self.select_prep.clone();
                    let tree_id_i64 = tree_id as i64;
                    let level_i8 = key.level as i8;
                    let index_i64 = key.index as i64;
                    let max_bh_i64 = if max_block_height > i64::MAX as u64 {
                        i64::MAX
                    } else {
                        max_block_height as i64
                    };
                    async move {
                        let res = session.execute_unpaged(&prep, (tree_id_i64, level_i8, index_i64, max_bh_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                            Hash::from_bytes(&row.0)
                        } else {
                            // Assume reverse_level = level for simplicity; adjust if tree height known
                            Ok(Hasher::get_zero_hash(key.level as usize))
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