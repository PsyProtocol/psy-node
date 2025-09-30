use std::sync::Arc;

use parth_core::data::serializable::{BinaryKVWithCheckpointId, QPDPair, QPDSerializable};
use scylla::{client::session::{Session, SessionConfig}, statement::{batch::Batch, prepared::PreparedStatement, Statement}};




const MAX_PREPARED_INSERT_BATCH_SIZE: usize = 128usize;
//const MAX_SELECT_SIZE: usize = 128usize;



pub struct ScyllaCoreStore {
    pub session: Arc<Session>,
    pub keyspace: String,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub prep_blob: ScyllaBlobPreparedStatements,
    pub prep_merkle: ScyllaMerkleNodesPreparedStatements,
    pub prep_double_merkle: ScyllaDoubleMerkleNodesPreparedStatements,
}
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

        let insert_1 = session.prepare(Statement::new("INSERT INTO checkpointed_kvs (node_key, checkpoint_id, node_value) VALUES (?, ?, ?)")).await?;
        let select_1 = session.prepare(Statement::new("SELECT node_value FROM checkpointed_kvs WHERE node_key = ? AND checkpoint_id <= ? LIMIT 1")).await?;
        let select_1_with_checkpoint = session.prepare(Statement::new("SELECT node_value, checkpoint_id FROM checkpointed_kvs WHERE node_key = ? AND checkpoint_id <= ? LIMIT 1")).await?;

        let select_2 = session.prepare(Statement::new("SELECT node_key, node_value from checkpointed_kvs WHERE node_key IN (?, ?) AND checkpoint_id <= ? PER PARTITION LIMIT 1")).await?;
        let select_15 = session.prepare(Statement::new("SELECT node_key, node_value from checkpointed_kvs WHERE node_key IN (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) AND checkpoint_id <= ? PER PARTITION LIMIT 1")).await?;

    let insert_prepared_alt = 
        session
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
    let select_all = session.prepare("SELECT node_key, checkpoint_id, node_value from checkpointed_kvs").await?;
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
}

#[derive(Debug, Clone)]
pub struct ScyllaMerkleNodesPreparedStatements {
    pub insert_1: Arc<PreparedStatement>,
    pub select_1: Arc<PreparedStatement>,

}

impl ScyllaMerkleNodesPreparedStatements {
    pub async fn new_from_session(session: Arc<Session>) -> anyhow::Result<Self> {
        let insert_stmt = Statement::new("INSERT INTO merkle_nodes (tree_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?)");
        let insert_prep = session.prepare(insert_stmt).await?;
        let select_stmt = Statement::new("SELECT value FROM merkle_nodes WHERE tree_id = ? AND level = ? AND node_index = ? AND checkpoint_id <= ? LIMIT 1");
        let select_prep = session.prepare(select_stmt).await?;

        Ok(Self {
            insert_1: Arc::new(insert_prep),
            select_1: Arc::new(select_prep),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ScyllaDoubleMerkleNodesPreparedStatements {
    pub insert_1: Arc<PreparedStatement>,
    pub select_1: Arc<PreparedStatement>,
}

impl ScyllaDoubleMerkleNodesPreparedStatements {
    pub async fn new_from_session(session: Arc<Session>) -> anyhow::Result<Self> {
        let insert_stmt = Statement::new("INSERT INTO double_merkle_nodes (tree_id, tree_sub_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?, ?)");
        let insert_prep = session.prepare(insert_stmt).await?;
        let select_stmt = Statement::new("SELECT value FROM double_merkle_nodes WHERE tree_id = ? AND tree_sub_id = ? AND level = ? AND node_index = ? AND checkpoint_id <= ? LIMIT 1");
        let select_prep = session.prepare(select_stmt).await?;

        Ok(Self {
            insert_1: Arc::new(insert_prep),
            select_1: Arc::new(select_prep),
        })
    }
}

impl ScyllaCoreStore {

    pub async fn new(realm_id: u64, realm_sub_id: u64, keyspace: String, known_nodes: &[String]) -> anyhow::Result<Self> {
        let mut config = SessionConfig::new();
        config.add_known_nodes(known_nodes.iter());
        let session = Arc::new(Session::connect(config).await?);

        // Create keyspace and table if not exists
        session
            .query_unpaged(
                format!("CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'SimpleStrategy', 'replication_factor': 1}}", &keyspace),
                &[],
            )
            .await?;
        session.await_schema_agreement().await?;
        session.use_keyspace(&keyspace, false).await?;
        session
            .query_unpaged(
                format!("CREATE TABLE IF NOT EXISTS {}.merkle_nodes (
                    tree_id BIGINT,
                    level TINYINT,
                    node_index BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((tree_id), level, node_index, checkpoint_id)
                ) WITH CLUSTERING ORDER BY (level ASC, node_index ASC, checkpoint_id DESC)", &keyspace),
                &[],
            ).await?;
        session.await_schema_agreement().await?;
        session
            .query_unpaged(
                format!("CREATE TABLE IF NOT EXISTS {}.double_merkle_nodes (
                    tree_id BIGINT,
                    tree_sub_id BIGINT,
                    level TINYINT,
                    node_index BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((tree_id, tree_sub_id), level, node_index, checkpoint_id)
                ) WITH CLUSTERING ORDER BY (level ASC, node_index ASC, checkpoint_id DESC)", &keyspace),
                &[],
            ).await?;
        session.await_schema_agreement().await?;
        session
            .query_unpaged(
                format!("CREATE TABLE IF NOT EXISTS {}.checkpointed_kvs (
                node_key blob,
                checkpoint_id bigint,
                node_value blob,
                PRIMARY KEY ((node_key), checkpoint_id)
            ) WITH CLUSTERING ORDER BY (checkpoint_id DESC)", &keyspace),
                &[],
            ).await?;
        session.await_schema_agreement().await?;
        // Prepare statements
        let prep_blob = ScyllaBlobPreparedStatements::new_from_session(session.clone()).await?;
        let prep_merkle = ScyllaMerkleNodesPreparedStatements::new_from_session(session.clone()).await?;
        let prep_double_merkle = ScyllaDoubleMerkleNodesPreparedStatements::new_from_session(session.clone()).await?;
        
        Ok(Self {
            session,
            keyspace,
            realm_id,
            realm_sub_id,
            prep_blob,
            prep_merkle,
            prep_double_merkle,
        })
    }
}


impl ScyllaCoreStore {
    pub async fn insert_checkpoint_kv_blob(&self, checkpoint_id: u64, node_key: &[u8], node_value: &[u8]) -> anyhow::Result<()> {
        let stmt = &self.prep_blob.insert_1;
        self.session.execute_unpaged(stmt, (node_key, checkpoint_id as i64, node_value)).await?;
        Ok(())
    }
    pub async fn insert_checkpoint_kv_obj<K: QPDSerializable, V: QPDSerializable>(&self, checkpoint_id: u64, node_key: &K, node_value: &V) -> anyhow::Result<()> {
        let stmt = &self.prep_blob.insert_1;
        self.session.execute_unpaged(stmt, (node_key.to_bytes()?, checkpoint_id as i64, node_value.to_bytes()?)).await?;
        Ok(())
    }
    pub async fn insert_checkpoint_kv_blobs(&self, checkpoint_id: u64, kvs: &[QPDPair<Vec<u8>, Vec<u8>>]) -> anyhow::Result<()> {

        if kvs.len() == 0 {
            return Ok(())
        }else if kvs.len() == 1 {
            return self.insert_checkpoint_kv_blob(checkpoint_id, &kvs[0].key, &kvs[0].value).await;
        }
        let remainder_nodes = kvs.len()%MAX_PREPARED_INSERT_BATCH_SIZE;
        let full_batches = kvs.len()/MAX_PREPARED_INSERT_BATCH_SIZE;


        let mut kvs_iter = kvs.iter();


        for _ in 0..full_batches {
            let mut row = Vec::with_capacity(MAX_PREPARED_INSERT_BATCH_SIZE);
            for (_, kv) in (0..MAX_PREPARED_INSERT_BATCH_SIZE).zip(&mut kvs_iter) {
                row.push((
                    &kv.key,
                    checkpoint_id as i64,
                    &kv.value
                ));
            }
            self.session.batch(&self.prep_blob.insert_prepared_batches[MAX_PREPARED_INSERT_BATCH_SIZE-1], row).await?;
        }

        if remainder_nodes != 0 {
            let mut row = Vec::with_capacity(MAX_PREPARED_INSERT_BATCH_SIZE);
            for kv in kvs_iter {
                row.push((
                    &kv.key,
                    checkpoint_id as i64,
                    &kv.value
                ));
            }
            self.session.batch(&self.prep_blob.insert_prepared_batches[remainder_nodes-1], row).await?;

        }


        //Vec::with_capacity(nodes.len());





        Ok(())
    }
    pub async fn insert_checkpoint_kv_objs<K: QPDSerializable, V: QPDSerializable>(&self, checkpoint_id: u64, kvs: &[QPDPair<K, V>]) -> anyhow::Result<()> {

        if kvs.len() == 0 {
            return Ok(())
        }else if kvs.len() == 1 {
            return self.insert_checkpoint_kv_obj(checkpoint_id, &kvs[0].key, &kvs[0].value).await;
        }
        let remainder_nodes = kvs.len()%MAX_PREPARED_INSERT_BATCH_SIZE;
        let full_batches = kvs.len()/MAX_PREPARED_INSERT_BATCH_SIZE;


        let mut kvs_iter = kvs.iter();


        for _ in 0..full_batches {
            let mut row = Vec::with_capacity(MAX_PREPARED_INSERT_BATCH_SIZE);
            for (_, kv) in (0..MAX_PREPARED_INSERT_BATCH_SIZE).zip(&mut kvs_iter) {
                row.push((
                    kv.key.to_bytes()?,
                    checkpoint_id as i64,
                    kv.value.to_bytes()?
                ));
            }
            self.session.batch(&self.prep_blob.insert_prepared_batches[MAX_PREPARED_INSERT_BATCH_SIZE-1], row).await?;
        }

        if remainder_nodes != 0 {
            let mut row = Vec::with_capacity(MAX_PREPARED_INSERT_BATCH_SIZE);
            for kv in kvs_iter {
                row.push((
                    kv.key.to_bytes()?,
                    checkpoint_id as i64,
                    kv.value.to_bytes()?
                ));
            }
            self.session.batch(&self.prep_blob.insert_prepared_batches[remainder_nodes-1], row).await?;

        }


        //Vec::with_capacity(nodes.len());





        Ok(())
    }

    pub async fn select_one_checkpoint_kv_blob(&self, checkpoint_id: u64, node_key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let stmt = &self.prep_blob.select_1;
        let res = self.session.execute_unpaged(stmt, (node_key, checkpoint_id as i64)).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => Ok(Some(row.0)),
            None => Ok(None),
        }
    }
    pub async fn select_one_checkpoint_kv_obj<K: QPDSerializable, V: QPDSerializable>(&self, checkpoint_id: u64, node_key: &K) -> anyhow::Result<Option<V>> {
        let key_bytes = node_key.to_bytes()?;
        let value_bytes_opt = self.select_one_checkpoint_kv_blob(checkpoint_id, &key_bytes).await?;
        match value_bytes_opt {
            Some(value_bytes) => {
                let value = V::from_bytes(&value_bytes)?;
                Ok(Some(value))
            },
            None => Ok(None),
        }
    }
    pub async fn select_one_checkpoint_kv_blob_with_checkpoint(&self, checkpoint_id: u64, node_key: &[u8]) -> anyhow::Result<Option<(Vec<u8>, u64)>> {
        let stmt = &self.prep_blob.select_1_with_checkpoint;
        let res = self.session.execute_unpaged(stmt, (node_key, checkpoint_id as i64)).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>, i64)>()? {
            Some(row) => Ok(Some((row.0, row.1 as u64))),
            None => Ok(None),
        }
    }
    pub async fn select_one_checkpoint_kv_obj_with_checkpoint<K: QPDSerializable, V: QPDSerializable>(&self, checkpoint_id: u64, node_key: &K) -> anyhow::Result<Option<(V, u64)>> {
        let key_bytes = node_key.to_bytes()?;
        let value_bytes_opt = self.select_one_checkpoint_kv_blob_with_checkpoint(checkpoint_id, &key_bytes).await?;
        match value_bytes_opt {
            Some((value_bytes, chkpt_id)) => {
                let value = V::from_bytes(&value_bytes)?;
                Ok(Some((value, chkpt_id)))
            },
            None => Ok(None),
        }
    }

    pub async fn select_all_checkpoint_kv_blobs(&self) -> anyhow::Result<Vec<BinaryKVWithCheckpointId>> {
        let stmt = &self.prep_blob.select_all;
        let res = self.session.execute_unpaged(stmt, ()).await?;
        let rows_result = res.into_rows_result()?;
        let rows_iter = rows_result.rows::<(Vec<u8>,i64,Vec<u8>)>()?;
        let rows_vec: Vec<_> = rows_iter.collect();
        let mut results = Vec::with_capacity(rows_vec.len());

        for row in rows_vec {
            let (node_key, checkpoint_id, node_value): (Vec<u8>, i64, Vec<u8>) = row?;
            results.push(BinaryKVWithCheckpointId {
                key: node_key,
                value: node_value,
                checkpoint_id: checkpoint_id as u64,
            });
        }
        Ok(results)
    }
}   