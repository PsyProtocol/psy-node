use std::sync::Arc;

use scylla::{
    client::session::Session,
    statement::{batch::Batch, prepared::PreparedStatement, Statement},
};

use crate::store::scylla::constants::MAX_PREPARED_INSERT_BATCH_SIZE;

#[derive(Clone)]
pub struct ScyllaBlobPreparedStatements {
    pub insert_1: Arc<PreparedStatement>,
    pub insert_prepared_batches: [Arc<Batch>; MAX_PREPARED_INSERT_BATCH_SIZE],
    pub select_1: Arc<PreparedStatement>,
    pub select_1_with_checkpoint: Arc<PreparedStatement>,
    pub select_2: Arc<PreparedStatement>,
    pub select_15: Arc<PreparedStatement>,
    pub select_all: Arc<PreparedStatement>,
}
impl ScyllaBlobPreparedStatements {
    pub async fn new_from_session(session: Arc<Session>) -> anyhow::Result<Self> {
        let insert_1 = session
            .prepare(Statement::new(
                "INSERT INTO checkpointed_kvs (node_key, checkpoint_id, node_value) VALUES (?, ?, ?)",
            ))
            .await?;
        let select_1 = session
            .prepare(Statement::new(
                "SELECT node_value FROM checkpointed_kvs WHERE node_key = ? AND checkpoint_id <= ? LIMIT 1",
            ))
            .await?;
        let select_1_with_checkpoint = session
            .prepare(Statement::new(
                "SELECT node_value, checkpoint_id FROM checkpointed_kvs WHERE node_key = ? AND checkpoint_id <= ? LIMIT 1",
            ))
            .await?;

        let select_2 = session
            .prepare(Statement::new(
                "SELECT node_key, node_value from checkpointed_kvs WHERE node_key IN (?, ?) AND checkpoint_id <= ? PER PARTITION LIMIT 1",
            ))
            .await?;
        let select_15 = session.prepare(Statement::new("SELECT node_key, node_value from checkpointed_kvs WHERE node_key IN (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) AND checkpoint_id <= ? PER PARTITION LIMIT 1")).await?;

        let insert_prepared_alt = session
            .prepare("INSERT INTO checkpointed_kvs (node_key, checkpoint_id, node_value) VALUES (?, ?, ?)")
            .await?;
        let mut batches: Vec<Arc<Batch>> = Vec::with_capacity(MAX_PREPARED_INSERT_BATCH_SIZE);
        for i in 0..MAX_PREPARED_INSERT_BATCH_SIZE {
            let mut batch: Batch = Default::default();
            for _ in 0..=i {
                batch.append_statement(insert_prepared_alt.clone());
            }
            let prepared_batch = session.prepare_batch(&batch).await?;
            batches.push(Arc::new(prepared_batch));
        }

        let insert_prepared_batches: [Arc<Batch>; MAX_PREPARED_INSERT_BATCH_SIZE] = match batches.try_into() {
            Ok(x) => x,
            Err(_) => anyhow::bail!("error preparing batches"),
        };
        let select_all = session
            .prepare("SELECT node_key, checkpoint_id, node_value from checkpointed_kvs")
            .await?;
        Ok(Self {
            insert_1: Arc::new(insert_1),
            insert_prepared_batches,
            select_1: Arc::new(select_1),
            select_1_with_checkpoint: Arc::new(select_1_with_checkpoint),
            select_2: Arc::new(select_2),
            select_15: Arc::new(select_15),
            select_all: Arc::new(select_all),
        })
    }
    pub async fn create_table(session: Arc<Session>, keyspace: &str) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {}.checkpointed_kvs (
                node_key blob,
                checkpoint_id bigint,
                node_value blob,
                PRIMARY KEY ((node_key), checkpoint_id)
            ) WITH CLUSTERING ORDER BY (checkpoint_id DESC)",
                    keyspace
                ),
                &[],
            )
            .await?;
        session.await_schema_agreement().await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct ScyllaMerkleNodesPreparedStatements {
    pub insert_1: Arc<PreparedStatement>,
    pub insert_1_statement: Statement,
    pub select_1: Arc<PreparedStatement>,
    pub select_1_statement: Statement,
}

impl ScyllaMerkleNodesPreparedStatements {
    pub async fn new_from_session(session: Arc<Session>) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new("INSERT INTO merkle_nodes (tree_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?)");
        let insert_prep = session.prepare(insert_1_statement.clone()).await?;
        let select_1_statement =
            Statement::new("SELECT value FROM merkle_nodes WHERE tree_id = ? AND level = ? AND node_index = ? AND checkpoint_id <= ? LIMIT 1");
        let select_prep = session.prepare(select_1_statement.clone()).await?;

        Ok(Self {
            insert_1: Arc::new(insert_prep),
            select_1: Arc::new(select_prep),
            insert_1_statement: insert_1_statement,
            select_1_statement: select_1_statement,
        })
    }
    pub async fn create_table(session: Arc<Session>, keyspace: &str) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {}.merkle_nodes (
                    tree_id BIGINT,
                    level TINYINT,
                    node_index BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((tree_id), level, node_index, checkpoint_id)
                ) WITH CLUSTERING ORDER BY (level ASC, node_index ASC, checkpoint_id DESC)",
                    keyspace
                ),
                &[],
            )
            .await?;
        session.await_schema_agreement().await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct ScyllaDoubleMerkleNodesPreparedStatements {
    pub insert_1: Arc<PreparedStatement>,
    pub insert_1_statement: Statement,
    pub select_1: Arc<PreparedStatement>,
    pub select_1_statement: Statement,
}

impl ScyllaDoubleMerkleNodesPreparedStatements {
    pub async fn new_from_session(session: Arc<Session>) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(
            "INSERT INTO double_merkle_nodes (tree_id, tree_sub_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?, ?)",
        );
        let insert_prep = session.prepare(insert_1_statement.clone()).await?;
        let select_1_statement = Statement::new("SELECT value FROM double_merkle_nodes WHERE tree_id = ? AND tree_sub_id = ? AND level = ? AND node_index = ? AND checkpoint_id <= ? LIMIT 1");
        let select_prep = session.prepare(select_1_statement.clone()).await?;

        Ok(Self {
            insert_1: Arc::new(insert_prep),
            select_1: Arc::new(select_prep),
            select_1_statement,
            insert_1_statement,
        })
    }
    pub async fn create_table(session: Arc<Session>, keyspace: &str) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {}.double_merkle_nodes (
                    tree_id BIGINT,
                    tree_sub_id BIGINT,
                    level TINYINT,
                    node_index BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((tree_id, tree_sub_id), level, node_index, checkpoint_id)
                ) WITH CLUSTERING ORDER BY (level ASC, node_index ASC, checkpoint_id DESC)",
                    keyspace
                ),
                &[],
            )
            .await?;
        session.await_schema_agreement().await?;
        Ok(())
    }
}
