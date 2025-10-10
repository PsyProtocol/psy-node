use std::sync::Arc;

use anyhow::Context;
use futures::future::join_all;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::{db::{row::{QDatabaseDoubleIdTableRow, QDatabaseDoubleIdTableRowCreatable, QDatabaseDoubleIdTableRowLike, QDatabaseDoubleIdTableRowNoCheckpointId, QDatabaseDoubleIdTableRowNoCheckpointIdLike, QDatabaseKeyIdValueTableRow, QDatabaseKeyIdValueTableRowCreatable, QDatabaseKeyIdValueTableRowLike, QDatabaseSingleIdTableRow, QDatabaseSingleIdTableRowCreatable, QDatabaseSingleIdTableRowLike, QDatabaseSingleIdTableRowNoCheckpointId, QDatabaseSingleIdTableRowNoCheckpointIdLike, QDoubleIdKey}, table::QDatabaseTableRoutingKey}, hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}}, protocol::core_types::QHashBase};
use scylla::{client::session::{Session, SessionConfig}, statement::batch::Batch};
use serde::{de::DeserializeOwned, Serialize};

use crate::{constants::{INSERT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE, INSERT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE, INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE, SELECT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE, SELECT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE, SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE}, tables::{merkle::{ScyllaDoubleMerkleNodesPreparedStatements, ScyllaMerkleNodesPreparedStatements, ScyllaMerkleNodesZeroPreparedStatements}, object::{ScyllaGenericKeyIdValueTablePreparedStatements, ScyllaGenericObjectDoubleIdTablePreparedStatements, ScyllaGenericObjectSingleIdTablePreparedStatements}}, utils::{convert_checkpoint_id_to_i64, convert_i64_to_checkpoint_id, i64_to_u64_exact, u64_to_i64_exact, u8_to_i8_exact}};






#[derive(Clone)]
pub struct ScyllaCoreStore<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>> {
    pub session: Arc<Session>,
    pub keyspace: String,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    _phantom_hash: std::marker::PhantomData<Hash>,
    _phantom_hasher: std::marker::PhantomData<Hasher>,
}

impl<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>  ScyllaCoreStore<Hash, Hasher> {

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
        Ok(Self {
            session,
            keyspace,
            realm_id,
            realm_sub_id,
            _phantom_hash: std::marker::PhantomData,
            _phantom_hasher: std::marker::PhantomData,
        })
    }
    pub async fn init_single_id_checkpointed(&self, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<ScyllaGenericObjectSingleIdTablePreparedStatements> {
       ScyllaGenericObjectSingleIdTablePreparedStatements::new_create_from_session(self.session.clone(), &self.keyspace, table_name, table_key).await
    }
    pub async fn init_double_id_checkpointed(&self, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<ScyllaGenericObjectDoubleIdTablePreparedStatements> {
               ScyllaGenericObjectDoubleIdTablePreparedStatements::new_create_from_session(self.session.clone(), &self.keyspace, table_name, table_key).await
    }
    pub async fn init_key_id_value(&self, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<ScyllaGenericKeyIdValueTablePreparedStatements> {
       ScyllaGenericKeyIdValueTablePreparedStatements::new_create_from_session(self.session.clone(), &self.keyspace, table_name, table_key).await
    }
    pub async fn init_single_merkle_table(&self, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<ScyllaMerkleNodesPreparedStatements> {
        ScyllaMerkleNodesPreparedStatements::new_create_from_session(self.session.clone(), &self.keyspace, table_name, table_key).await
    }
    pub async fn init_double_merkle_table(&self, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<ScyllaDoubleMerkleNodesPreparedStatements> {
        ScyllaDoubleMerkleNodesPreparedStatements::new_create_from_session(self.session.clone(), &self.keyspace, table_name, table_key).await
    }
}

impl<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>  ScyllaCoreStore<Hash, Hasher> {
    pub async fn select_zero_id_merkle_node_max_checkpoint_internal<const TREE_HEIGHT: u8>(&self, merkle_prepared: &ScyllaMerkleNodesZeroPreparedStatements<TREE_HEIGHT>, checkpoint_id: u64, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash> {
        let res = self.session.execute_unpaged(&merkle_prepared.select_1_prepared, (u8_to_i8_exact(key.level), u64_to_i64_exact(key.index), convert_checkpoint_id_to_i64(checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => Ok(Hash::from_bytes(&row.0)?),
            None => Ok(Hasher::get_zero_hash((TREE_HEIGHT - key.level) as usize)), // Return zero hash if not found
        }
    }

    pub async fn select_many_zero_id_merkle_nodes_max_checkpoint_internal<const TREE_HEIGHT: u8>(
        &self,
        merkle_prepared: &ScyllaMerkleNodesZeroPreparedStatements<TREE_HEIGHT>,
        max_checkpoint_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        const CONCURRENT_LIMIT: usize = 256; // Batch concurrent queries
        let mut results = Vec::with_capacity(keys.len());
        for chunk in keys.chunks(CONCURRENT_LIMIT) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = self.session.clone();
                    let prep = merkle_prepared.select_1_prepared.clone();
                    let level_i8 = u8_to_i8_exact(key.level);
                    let index_i64 = u64_to_i64_exact(key.index);
                    let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
                    async move {
                        let res = session.execute_unpaged(&prep, (level_i8, index_i64, max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                            Hash::from_bytes(&row.0)
                        } else {
                            // Assume reverse_level = level for simplicity; adjust if tree height known
                            Ok(Hasher::get_zero_hash((TREE_HEIGHT-key.level) as usize))
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
    pub async fn insert_zero_id_merkle_node_internal<const TREE_HEIGHT: u8>(&self, merkle_prepared: &ScyllaMerkleNodesZeroPreparedStatements<TREE_HEIGHT>,checkpoint_id: u64, key: SimpleMerkleNodeKey, value: &[u8]) -> anyhow::Result<()> {
        self.session.execute_unpaged(&merkle_prepared.insert_1_prepared, (u8_to_i8_exact(key.level), u64_to_i64_exact(key.index), u64_to_i64_exact(checkpoint_id), value)).await?;
        Ok(())
    }
    pub async fn set_zero_id_merkle_nodes_batch_internal<const TREE_HEIGHT: u8>(
        &self,
        merkle_prepared: &ScyllaMerkleNodesZeroPreparedStatements<TREE_HEIGHT>,
        checkpoint_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()> {
        const BATCH_SIZE: usize = 256; // Safe batch size to avoid payload limits
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, level, node_index, checkpoint_id, value
        let mut value_list: Vec<Vec<(i8, i64, i64, Vec<u8>)>> = Vec::new();
        let checkpoint_i64 = convert_checkpoint_id_to_i64(checkpoint_id);
        for chunk in nodes.chunks(BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(merkle_prepared.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u8_to_i8_exact(n.key.level), u64_to_i64_exact(n.key.index), checkpoint_i64, n.value.to_bytes()?))
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
}

impl<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>  ScyllaCoreStore<Hash, Hasher> {

    pub async fn select_single_id_merkle_node_max_checkpoint_internal(&self, merkle_prepared: &ScyllaMerkleNodesPreparedStatements, checkpoint_id: u64, tree_id: u64, tree_height: u8, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash> {
        let res = self.session.execute_unpaged(&merkle_prepared.select_1_prepared, (u64_to_i64_exact(tree_id), u8_to_i8_exact(key.level), u64_to_i64_exact(key.index), convert_checkpoint_id_to_i64(checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => Ok(Hash::from_bytes(&row.0)?),
            None => Ok(Hasher::get_zero_hash((tree_height - key.level) as usize)), // Return zero hash if not found
        }
    }


    pub async fn select_many_single_id_merkle_nodes_max_checkpoint_internal(
        &self,
        merkle_prepared: &ScyllaMerkleNodesPreparedStatements,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        const CONCURRENT_LIMIT: usize = 256; // Batch concurrent queries
        let mut results = Vec::with_capacity(keys.len());
        for chunk in keys.chunks(CONCURRENT_LIMIT) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = self.session.clone();
                    let prep = merkle_prepared.select_1_prepared.clone();
                    let tree_id_i64 = u64_to_i64_exact(tree_id);
                    let level_i8 = u8_to_i8_exact(key.level);
                    let index_i64 = u64_to_i64_exact(key.index);
                    let max_cp_i64 = if max_checkpoint_id > i64::MAX as u64 {
                        i64::MAX
                    } else {
                        max_checkpoint_id as i64
                    };
                    async move {
                        let res = session.execute_unpaged(&prep, (tree_id_i64, level_i8, index_i64, max_cp_i64)).await?;
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
    pub async fn insert_single_id_merkle_node_internal(&self, merkle_prepared: &ScyllaMerkleNodesPreparedStatements,checkpoint_id: u64, tree_id: u64, key: SimpleMerkleNodeKey, value: &[u8]) -> anyhow::Result<()> {
        self.session.execute_unpaged(&merkle_prepared.insert_1_prepared, (u64_to_i64_exact(tree_id), u8_to_i8_exact(key.level), u64_to_i64_exact(key.index), u64_to_i64_exact(checkpoint_id), value)).await?;
        Ok(())
    }
    pub async fn set_single_id_merkle_nodes_batch_internal(
        &self,
        merkle_prepared: &ScyllaMerkleNodesPreparedStatements,
        checkpoint_id: u64,
        tree_id: u64,
        nodes: Vec<SimpleMerkleNode<Hash>>,
    ) -> anyhow::Result<()> {
        const BATCH_SIZE: usize = 256; // Safe batch size to avoid payload limits
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, level, node_index, checkpoint_id, value
        let mut value_list: Vec<Vec<(i64, i8, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in nodes.chunks(BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(merkle_prepared.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(tree_id), u8_to_i8_exact(n.key.level), u64_to_i64_exact(n.key.index), checkpoint_id as i64, n.value.to_bytes()?))
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
    pub async fn set_double_id_merkle_nodes_batch_internal(
        &self,
        double_merkle_prepared: &ScyllaDoubleMerkleNodesPreparedStatements,
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
                batch.append_statement(double_merkle_prepared.insert_1_statement.clone());
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
        let batches: Vec<_> = batch_list.iter().zip(value_list.into_iter()).map(|(batch, values)| self.session.batch(batch, values)).collect();
        let results = join_all(batches).await;
        for res in results {
            res.context("Batch insert failed")?;
        }
        Ok(())
    }
    pub async fn select_double_id_merkle_node_max_checkpoint_internal(&self, double_merkle_prepared: &ScyllaDoubleMerkleNodesPreparedStatements, checkpoint_id: u64, tree_id: u64, tree_height: u8, tree_secondary_id: u64, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash> {
        let res = self.session.execute_unpaged(&double_merkle_prepared.select_1_prepared, (u64_to_i64_exact(tree_id), u64_to_i64_exact(tree_secondary_id), u8_to_i8_exact(key.level), u64_to_i64_exact(key.index), convert_checkpoint_id_to_i64(checkpoint_id))).await?;
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


    pub async fn select_many_double_id_merkle_nodes_max_checkpoint_internal(
        &self,
        double_merkle_prepared: &ScyllaDoubleMerkleNodesPreparedStatements,
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
                    let session = self.session.clone();
                    let prep = double_merkle_prepared.select_1_prepared.clone();
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
    pub async fn insert_double_id_merkle_node_internal(&self, double_merkle_prepared: &ScyllaDoubleMerkleNodesPreparedStatements, checkpoint_id: u64, tree_id: u64, tree_secondary_id: u64, key: SimpleMerkleNodeKey, value: &[u8]) -> anyhow::Result<()> {
        self.session.execute_unpaged(&double_merkle_prepared.insert_1_prepared, (u64_to_i64_exact(tree_id), u64_to_i64_exact(tree_secondary_id), u8_to_i8_exact(key.level), u64_to_i64_exact(key.index), convert_checkpoint_id_to_i64(checkpoint_id), value)).await?;
        Ok(())
    }

}   



impl<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>  ScyllaCoreStore<Hash, Hasher> {

    pub async fn select_one_single_checkpointed_object_value<V: Serialize + DeserializeOwned>(
        &self, 
        single_prepared: &ScyllaGenericObjectSingleIdTablePreparedStatements, 
        obj_id: u64, 
        max_checkpoint_id: u64
    ) -> anyhow::Result<Option<V>> {
        let res = self.session.execute_unpaged(&single_prepared.select_value_1_prepared, (u64_to_i64_exact(obj_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => match pser::deserialize::<V>(&row.0) {
                Ok(value) => Ok(Some(value)),
                Err(e) => {
                    tracing::error!("Deserialization error for latest object ID with {} in table {}.{}: {:?}", obj_id, single_prepared.keyspace, single_prepared.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None), // Return zero hash if not found
        }
    }
    pub async fn select_one_single_checkpointed_object_value_and_ids<V: Serialize + DeserializeOwned>(
        &self, 
        single_prepared: &ScyllaGenericObjectSingleIdTablePreparedStatements, 
        obj_id: u64, 
        max_checkpoint_id: u64
    ) -> anyhow::Result<Option<QDatabaseSingleIdTableRow<V>>> {
        let res = self.session.execute_unpaged(&single_prepared.select_value_checkpoint_id_obj_id_1_prepared, (u64_to_i64_exact(obj_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, i64, Vec<u8>)>()? {

            Some(row) => match pser::deserialize::<V>(&row.2) {
                Ok(value) => 
                    Ok(Some(QDatabaseSingleIdTableRow {
                    value,
                    obj_id: i64_to_u64_exact(row.0),
                    checkpoint_id: convert_i64_to_checkpoint_id(row.1),
                })),
                Err(e) => {
                    tracing::error!("Deserialization error for object ID {} at checkpoint_id={} in {}.{}: {:?}", obj_id, convert_i64_to_checkpoint_id(row.1), single_prepared.keyspace, single_prepared.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None), // Return zero hash if not found
        }
    }
    pub async fn select_one_single_checkpointed_object_value_and_ids_t<V: Serialize + DeserializeOwned, R: QDatabaseSingleIdTableRowCreatable<V>>(
        &self, 
        single_prepared: &ScyllaGenericObjectSingleIdTablePreparedStatements, 
        obj_id: u64, 
        max_checkpoint_id: u64
    ) -> anyhow::Result<Option<R>> {
        let res = self.session.execute_unpaged(&single_prepared.select_value_checkpoint_id_obj_id_1_prepared, (u64_to_i64_exact(obj_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, i64, Vec<u8>)>()? {
            Some(row) => match pser::deserialize::<V>(&row.2) {
                Ok(value) => Ok(Some(R::create_from_single_row(i64_to_u64_exact(row.0), convert_i64_to_checkpoint_id(row.1), value))),
                Err(e) => {
                    tracing::error!("Deserialization error for object ID {} at checkpoint_id={} in {}.{}: {:?}", obj_id, convert_i64_to_checkpoint_id(row.1), single_prepared.keyspace, single_prepared.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None), // Return zero hash if not found
        }
    }


    
    pub async fn select_all_single_checkpointed_object<V: Serialize + DeserializeOwned>(
        &self, 
        single_prepared: &ScyllaGenericObjectSingleIdTablePreparedStatements, 
    ) -> anyhow::Result<Vec<QDatabaseSingleIdTableRow<V>>> {
        let res = self.session.execute_unpaged(&single_prepared.select_all_prepared, ()).await?;
        let rows_result = res.into_rows_result()?;
        let rows_iter = rows_result.rows::<(i64,i64,Vec<u8>)>()?;
        let rows_vec: Vec<_> = rows_iter.collect();
        let mut results = Vec::with_capacity(rows_vec.len());

        for row in rows_vec {
            let (obj_id, checkpoint_id, value): (i64, i64, Vec<u8>) = row?;
            results.push(QDatabaseSingleIdTableRow {
                obj_id: i64_to_u64_exact(obj_id),
                checkpoint_id: convert_i64_to_checkpoint_id(checkpoint_id),
                value: match pser::deserialize(&value){
                    Ok(value) => value,
                    Err(e) => {
                        tracing::error!("Deserialization error for object ID {} at checkpoint_id={} in {}.{}: {:?}", obj_id, convert_i64_to_checkpoint_id(checkpoint_id), single_prepared.keyspace, single_prepared.table_name, e);
                        anyhow::bail!("Deserialization error for object ID {} at checkpoint_id={} in {}.{}: {:?}", obj_id, convert_i64_to_checkpoint_id(checkpoint_id), single_prepared.keyspace, single_prepared.table_name, e);
                    }
                },
            });
        }
        Ok(results)
    }


    pub async fn insert_one_single_checkpointed_object<V: Serialize>(
        &self, 
        single_prepared: &ScyllaGenericObjectSingleIdTablePreparedStatements, 
        obj_id: u64, 
        checkpoint_id: u64, 
        value: &V
    ) -> anyhow::Result<()> {
        let value_bytes = pser::serialize(value)?;
        self.session.execute_unpaged(&single_prepared.insert_1_prepared, (u64_to_i64_exact(obj_id), u64_to_i64_exact(checkpoint_id), &value_bytes)).await?;
        Ok(())
    }
    pub async fn insert_many_single_checkpointed_object_rows<V: Serialize>(
        &self, 
        single_prepared: &ScyllaGenericObjectSingleIdTablePreparedStatements, 
        rows: &[QDatabaseSingleIdTableRow<V>]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let mut value_list: Vec<Vec<(i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(single_prepared.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.obj_id), convert_checkpoint_id_to_i64(n.checkpoint_id), pser::serialize(&n.value)?))
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

    pub async fn insert_many_single_checkpointed_object_rows_t<V: Serialize + DeserializeOwned, R: QDatabaseSingleIdTableRowLike<V>>(
        &self, 
        single_prepared: &ScyllaGenericObjectSingleIdTablePreparedStatements, 
        rows: &[R]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let mut value_list: Vec<Vec<(i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(single_prepared.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.get_row_obj_id()), convert_checkpoint_id_to_i64(n.get_row_checkpoint_id()), pser::serialize(&n.get_row_value_ref())?))
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
    pub async fn insert_many_single_checkpointed_objects_at_checkpoint<V: Serialize>(
        &self, 
        single_prepared: &ScyllaGenericObjectSingleIdTablePreparedStatements, 
        checkpoint_id: u64,
        rows: &[QDatabaseSingleIdTableRowNoCheckpointId<V>]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let mut value_list: Vec<Vec<(i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(single_prepared.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.obj_id), convert_checkpoint_id_to_i64(checkpoint_id), pser::serialize(&n.value)?))
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
    pub async fn insert_many_single_checkpointed_objects_at_checkpoint_t<V: Serialize + DeserializeOwned, R: QDatabaseSingleIdTableRowNoCheckpointIdLike<V>>(
        &self, 
        single_prepared: &ScyllaGenericObjectSingleIdTablePreparedStatements, 
        checkpoint_id: u64,
        rows: &[R]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let mut value_list: Vec<Vec<(i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(single_prepared.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.get_row_obj_id()), convert_checkpoint_id_to_i64(checkpoint_id), pser::serialize(&n.get_row_value_ref())?))
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
    pub async fn select_many_single_checkpointed_object_values<V: Serialize + DeserializeOwned>(
        &self, 
        single_prepared: &ScyllaGenericObjectSingleIdTablePreparedStatements, 
        obj_ids: &[u64], 
        max_checkpoint_id: u64
    ) -> anyhow::Result<Vec<Option<V>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
        let obj_ids_i64 = obj_ids.iter().map(|id| u64_to_i64_exact(*id)).collect::<Vec<_>>();
        for chunk in obj_ids_i64.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = self.session.clone();
                    let prep = single_prepared.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key, max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                            match pser::deserialize::<V>(&row.0) {
                                Ok(value) => core::result::Result::<_, anyhow::Error>::Ok(Some(value)),
                                Err(e) => {
                                    tracing::error!("Deserialization error for object ID {} with max_checkpoint_id={} in {}.{}: {:?}", i64_to_u64_exact(*key), max_checkpoint_id, single_prepared.keyspace, single_prepared.table_name, e);
                                    Ok(None)
                                }
                            }
                        } else {
                            // Assume reverse_level = level for simplicity; adjust if tree height known
                            Ok(None)
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
    pub async fn select_many_single_checkpointed_object_keys_and_values<V: Serialize + DeserializeOwned, R: QDatabaseSingleIdTableRowCreatable<V>>(
        &self, 
        single_prepared: &ScyllaGenericObjectSingleIdTablePreparedStatements, 
        obj_ids: &[u64], 
        max_checkpoint_id: u64
    ) -> anyhow::Result<Vec<R>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
        let obj_ids_i64 = obj_ids.iter().map(|id| u64_to_i64_exact(*id)).collect::<Vec<_>>();
        for chunk in obj_ids_i64.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = self.session.clone();
                    let prep = single_prepared.select_value_checkpoint_id_obj_id_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key, max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(i64, i64, Vec<u8>)>()? {
                            match pser::deserialize::<V>(&row.2) {
                                Ok(value) => core::result::Result::<_, anyhow::Error>::Ok(Some(R::create_from_single_row(i64_to_u64_exact(row.0), convert_i64_to_checkpoint_id(row.1), value))),
                                Err(e) => {
                                    tracing::error!("Deserialization error for object ID {} at checkpoint_id={} in {}.{}: {:?}", i64_to_u64_exact(*key), convert_i64_to_checkpoint_id(row.1), single_prepared.keyspace, single_prepared.table_name, e);
                                    Ok(None)
                                }
                            }
                        } else {
                            // Assume reverse_level = level for simplicity; adjust if tree height known
                            Ok(None)
                        }
                    }
                })
                .collect();
            let chunk_results = join_all(futures).await;
            for res in chunk_results {
                let r = res?;
                if let Some(r) = r {
                    results.push(r);
                }
            }
        }
        Ok(results)
    }


}


impl<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>  ScyllaCoreStore<Hash, Hasher> {

    pub async fn select_one_double_checkpointed_object_value<V: Serialize + DeserializeOwned>(
        &self, 
        double_prepared: &ScyllaGenericObjectDoubleIdTablePreparedStatements, 
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64
    ) -> anyhow::Result<Option<V>> {
        let res = self.session.execute_unpaged(&double_prepared.select_value_1_prepared, (u64_to_i64_exact(obj_id), u64_to_i64_exact(secondary_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => match pser::deserialize::<V>(&row.0) {
                Ok(value) => Ok(Some(value)),
                Err(e) => {
                    tracing::error!("Deserialization error for latest object ID with ({}, {}) in table {}.{}: {:?}", obj_id, secondary_id, double_prepared.keyspace, double_prepared.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None), // Return zero hash if not found
        }
    }
    pub async fn select_one_double_checkpointed_object_value_and_ids<V: Serialize + DeserializeOwned>(
        &self, 
        double_prepared: &ScyllaGenericObjectDoubleIdTablePreparedStatements, 
        obj_id: u64, 
        secondary_id: u64,
        max_checkpoint_id: u64
    ) -> anyhow::Result<Option<QDatabaseDoubleIdTableRow<V>>> {
        let res = self.session.execute_unpaged(&double_prepared.select_value_checkpoint_id_obj_ids_1_prepared, (u64_to_i64_exact(obj_id), u64_to_i64_exact(secondary_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, i64, i64, Vec<u8>)>()? {
            Some(row) => match pser::deserialize::<V>(&row.3) {
                Ok(value) => Ok(Some(QDatabaseDoubleIdTableRow {
                    value,
                    obj_id: i64_to_u64_exact(row.0),
                    secondary_id: i64_to_u64_exact(row.1),
                    checkpoint_id: convert_i64_to_checkpoint_id(row.2),
                })),
                Err(e) => {
                    tracing::error!("Deserialization error for object ID ({}, {}) at checkpoint_id={} in {}.{}: {:?}", obj_id, secondary_id, convert_i64_to_checkpoint_id(row.2), double_prepared.keyspace, double_prepared.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None), // Return zero hash if not found
        }
    }
    pub async fn select_one_double_checkpointed_object_value_and_ids_t<V: Serialize + DeserializeOwned, R: QDatabaseDoubleIdTableRowCreatable<V>>(
        &self, 
        double_prepared: &ScyllaGenericObjectDoubleIdTablePreparedStatements, 
        obj_id: u64, 
        secondary_id: u64,
        max_checkpoint_id: u64
    ) -> anyhow::Result<Option<R>> {
        let res = self.session.execute_unpaged(&double_prepared.select_value_checkpoint_id_obj_ids_1_prepared, (u64_to_i64_exact(obj_id), u64_to_i64_exact(secondary_id), convert_checkpoint_id_to_i64(max_checkpoint_id))).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, i64, i64, Vec<u8>)>()? {
            Some(row) => match pser::deserialize::<V>(&row.3) {
                Ok(value) => Ok(Some(R::create_from_double_row(i64_to_u64_exact(row.0), i64_to_u64_exact(row.1), convert_i64_to_checkpoint_id(row.2), value))),
                Err(e) => {
                    tracing::error!("Deserialization error for object ID ({}, {}) at checkpoint_id={} in {}.{}: {:?}", obj_id, secondary_id, convert_i64_to_checkpoint_id(row.2), double_prepared.keyspace, double_prepared.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None), // Return zero hash if not found
        }
    }
    pub async fn select_all_double_checkpointed_object<V: Serialize + DeserializeOwned>(
        &self, 
        double_prepared: &ScyllaGenericObjectDoubleIdTablePreparedStatements, 
    ) -> anyhow::Result<Vec<QDatabaseDoubleIdTableRow<V>>> {
        let res = self.session.execute_unpaged(&double_prepared.select_all_prepared, ()).await?;
        let rows_result = res.into_rows_result()?;
        let rows_iter = rows_result.rows::<(i64,i64,i64,Vec<u8>)>()?;
        let rows_vec: Vec<_> = rows_iter.collect();
        let mut results = Vec::with_capacity(rows_vec.len());

        for row in rows_vec {
            let (obj_id, secondary_id, checkpoint_id, value): (i64, i64, i64, Vec<u8>) = row?;
            results.push(QDatabaseDoubleIdTableRow {
                obj_id: i64_to_u64_exact(obj_id),
                secondary_id: i64_to_u64_exact(secondary_id),
                checkpoint_id: convert_i64_to_checkpoint_id(checkpoint_id),
                value: match pser::deserialize(&value){
                    Ok(value) => value,
                    Err(e) => {
                        tracing::error!("Deserialization error for object ID ({}, {}) at checkpoint_id={} in {}.{}: {:?}", obj_id, secondary_id, convert_i64_to_checkpoint_id(checkpoint_id), double_prepared.keyspace, double_prepared.table_name, e);
                        anyhow::bail!("Deserialization error for object ID ({}, {}) at checkpoint_id={} in {}.{}: {:?}", obj_id, secondary_id, convert_i64_to_checkpoint_id(checkpoint_id), double_prepared.keyspace, double_prepared.table_name, e);
                    }
                },
            });
        }
        Ok(results)
    }


    pub async fn insert_one_double_checkpointed_object<V: Serialize>(
        &self, 
        double_prepared: &ScyllaGenericObjectDoubleIdTablePreparedStatements, 
        obj_id: u64, 
        secondary_id: u64,
        checkpoint_id: u64, 
        value: &V
    ) -> anyhow::Result<()> {
        let value_bytes = pser::serialize(value)?;
        self.session.execute_unpaged(&double_prepared.insert_1_prepared, (u64_to_i64_exact(obj_id), u64_to_i64_exact(secondary_id), u64_to_i64_exact(checkpoint_id), &value_bytes)).await?;
        Ok(())
    }
    pub async fn insert_many_double_checkpointed_object_rows<V: Serialize>(
        &self, 
        double_prepared: &ScyllaGenericObjectDoubleIdTablePreparedStatements, 
        rows: &[QDatabaseDoubleIdTableRow<V>]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(double_prepared.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.obj_id), u64_to_i64_exact(n.secondary_id), convert_checkpoint_id_to_i64(n.checkpoint_id), pser::serialize(&n.value)?))
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

    pub async fn insert_many_double_checkpointed_object_rows_t<V: Serialize + DeserializeOwned, R: QDatabaseDoubleIdTableRowLike<V>>(
        &self, 
        double_prepared: &ScyllaGenericObjectDoubleIdTablePreparedStatements, 
        rows: &[R]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(double_prepared.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.get_row_obj_id()), u64_to_i64_exact(n.get_row_secondary_id()), convert_checkpoint_id_to_i64(n.get_row_checkpoint_id()), pser::serialize(&n.get_row_value_ref())?))
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
    pub async fn insert_many_double_checkpointed_objects_at_checkpoint<V: Serialize>(
        &self, 
        double_prepared: &ScyllaGenericObjectDoubleIdTablePreparedStatements, 
        checkpoint_id: u64,
        rows: &[QDatabaseDoubleIdTableRowNoCheckpointId<V>]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(double_prepared.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.obj_id), u64_to_i64_exact(n.secondary_id), convert_checkpoint_id_to_i64(checkpoint_id), pser::serialize(&n.value)?))
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
    pub async fn insert_many_double_checkpointed_objects_at_checkpoint_t<V: Serialize + DeserializeOwned, R: QDatabaseDoubleIdTableRowNoCheckpointIdLike<V>>(
        &self, 
        double_prepared: &ScyllaGenericObjectDoubleIdTablePreparedStatements, 
        checkpoint_id: u64,
        rows: &[R]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, i64, i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(double_prepared.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.get_row_obj_id()), u64_to_i64_exact(n.get_row_secondary_id()), convert_checkpoint_id_to_i64(checkpoint_id), pser::serialize(&n.get_row_value_ref())?))
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
    pub async fn select_many_double_checkpointed_object_values<V: Serialize + DeserializeOwned>(
        &self, 
        double_prepared: &ScyllaGenericObjectDoubleIdTablePreparedStatements, 
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64
    ) -> anyhow::Result<Vec<Option<V>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
        for chunk in obj_ids.chunks(SELECT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = self.session.clone();
                    let prep = double_prepared.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (u64_to_i64_exact(key.obj_id), u64_to_i64_exact(key.secondary_id), max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                            match pser::deserialize::<V>(&row.0) {
                                Ok(value) => core::result::Result::<_, anyhow::Error>::Ok(Some(value)),
                                Err(e) => {
                                    tracing::error!("Deserialization error for object ID ({},{}) with max_checkpoint_id={} in {}.{}: {:?}", key.obj_id, key.secondary_id, convert_i64_to_checkpoint_id(max_cp_i64), double_prepared.keyspace, double_prepared.table_name, e);
                                    Ok(None)
                                }
                            }
                        } else {
                            // Assume reverse_level = level for simplicity; adjust if tree height known
                            Ok(None)
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
    pub async fn select_many_double_checkpointed_object_keys_and_values<V: Serialize + DeserializeOwned, R: QDatabaseDoubleIdTableRowCreatable<V>>(
        &self, 
        double_prepared: &ScyllaGenericObjectDoubleIdTablePreparedStatements, 
        obj_ids: &[QDoubleIdKey], 
        max_checkpoint_id: u64
    ) -> anyhow::Result<Vec<R>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let max_cp_i64 = convert_checkpoint_id_to_i64(max_checkpoint_id);
        for chunk in obj_ids.chunks(SELECT_DOUBLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = self.session.clone();
                    let prep = double_prepared.select_value_checkpoint_id_obj_ids_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (u64_to_i64_exact(key.obj_id), u64_to_i64_exact(key.secondary_id), max_cp_i64)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(i64, i64, i64, Vec<u8>)>()? {
                            match pser::deserialize::<V>(&row.3) {
                                Ok(value) => core::result::Result::<_, anyhow::Error>::Ok(Some(R::create_from_double_row(i64_to_u64_exact(row.0), i64_to_u64_exact(row.1), convert_i64_to_checkpoint_id(row.2), value))),
                                Err(e) => {
                                    tracing::error!("Deserialization error for object ID ({},{}) at checkpoint_id={} in {}.{}: {:?}", key.obj_id, key.secondary_id, convert_i64_to_checkpoint_id(row.2), double_prepared.keyspace, double_prepared.table_name, e);
                                    Ok(None)
                                }
                            }
                        } else {
                            // Assume reverse_level = level for simplicity; adjust if tree height known
                            Ok(None)
                        }
                    }
                })
                .collect();
            let chunk_results = join_all(futures).await;
            for res in chunk_results {
                let r = res?;
                if let Some(r) = r {
                    results.push(r);
                }
            }
        }
        Ok(results)
    }


}





impl<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>  ScyllaCoreStore<Hash, Hasher> {

    pub async fn select_one_kiv_value<V: Serialize + DeserializeOwned>(
        &self, 
        single_prepared: &ScyllaGenericKeyIdValueTablePreparedStatements, 
        obj_id: u64
    ) -> anyhow::Result<Option<V>> {
        let res = self.session.execute_unpaged(&single_prepared.select_value_1_prepared, (u64_to_i64_exact(obj_id),)).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(Vec<u8>,)>()? {
            Some(row) => match pser::deserialize::<V>(&row.0) {
                Ok(value) => Ok(Some(value)),
                Err(e) => {
                    tracing::error!("Deserialization error for latest object ID with {} in table {}.{}: {:?}", obj_id, single_prepared.keyspace, single_prepared.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None), // Return zero hash if not found
        }
    }
    pub async fn select_one_kiv_value_and_ids<V: Serialize + DeserializeOwned>(
        &self, 
        single_prepared: &ScyllaGenericKeyIdValueTablePreparedStatements, 
        obj_id: u64
    ) -> anyhow::Result<Option<QDatabaseKeyIdValueTableRow<V>>> {
        let res = self.session.execute_unpaged(&single_prepared.select_value_obj_id_1_prepared, (u64_to_i64_exact(obj_id),)).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, Vec<u8>)>()? {

            Some(row) => match pser::deserialize::<V>(&row.1) {
                Ok(value) => 
                    Ok(Some(QDatabaseKeyIdValueTableRow {
                    value,
                    obj_id: i64_to_u64_exact(row.0),
                })),
                Err(e) => {
                    tracing::error!("Deserialization error for object ID {} in {}.{}: {:?}", obj_id, single_prepared.keyspace, single_prepared.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None), // Return zero hash if not found
        }
    }
    pub async fn select_one_kiv_value_and_ids_t<V: Serialize + DeserializeOwned, R: QDatabaseKeyIdValueTableRowCreatable<V>>(
        &self, 
        single_prepared: &ScyllaGenericKeyIdValueTablePreparedStatements, 
        obj_id: u64, 
    ) -> anyhow::Result<Option<R>> {
        let res = self.session.execute_unpaged(&single_prepared.select_value_obj_id_1_prepared, (u64_to_i64_exact(obj_id),)).await?;
        let rows = res.into_rows_result()?;
        match rows.maybe_first_row::<(i64, Vec<u8>)>()? {
            Some(row) => match pser::deserialize::<V>(&row.1) {
                Ok(value) => Ok(Some(R::create_from_key_id_value_row(i64_to_u64_exact(row.0), value))),
                Err(e) => {
                    tracing::error!("Deserialization error for object ID {} in {}.{}: {:?}", obj_id, single_prepared.keyspace, single_prepared.table_name, e);
                    Ok(None)
                }
            },
            None => Ok(None), // Return zero hash if not found
        }
    }


    
    pub async fn select_all_kiv<V: Serialize + DeserializeOwned>(
        &self, 
        single_prepared: &ScyllaGenericKeyIdValueTablePreparedStatements, 
    ) -> anyhow::Result<Vec<QDatabaseKeyIdValueTableRow<V>>> {
        let res = self.session.execute_unpaged(&single_prepared.select_all_prepared, ()).await?;
        let rows_result = res.into_rows_result()?;
        let rows_iter = rows_result.rows::<(i64,Vec<u8>)>()?;
        let rows_vec: Vec<_> = rows_iter.collect();
        let mut results = Vec::with_capacity(rows_vec.len());

        for row in rows_vec {
            let (obj_id, value): (i64, Vec<u8>) = row?;
            results.push(QDatabaseKeyIdValueTableRow {
                obj_id: i64_to_u64_exact(obj_id),
                value: match pser::deserialize(&value){
                    Ok(value) => value,
                    Err(e) => {
                        tracing::error!("Deserialization error for object ID {} in {}.{}: {:?}", obj_id, single_prepared.keyspace, single_prepared.table_name, e);
                        anyhow::bail!("Deserialization error for object ID {} in {}.{}: {:?}", obj_id, single_prepared.keyspace, single_prepared.table_name, e);
                    }
                },
            });
        }
        Ok(results)
    }


    pub async fn insert_one_kiv<V: Serialize>(
        &self, 
        single_prepared: &ScyllaGenericKeyIdValueTablePreparedStatements, 
        obj_id: u64, 
        value: &V
    ) -> anyhow::Result<()> {
        let value_bytes = pser::serialize(value)?;
        self.session.execute_unpaged(&single_prepared.insert_1_prepared, (u64_to_i64_exact(obj_id), &value_bytes)).await?;
        Ok(())
    }

    pub async fn insert_many_kiv_rows_t<V: Serialize + DeserializeOwned, R: QDatabaseKeyIdValueTableRowLike<V>>(
        &self, 
        single_prepared: &ScyllaGenericKeyIdValueTablePreparedStatements, 
        rows: &[R]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(single_prepared.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.get_row_obj_id()),  pser::serialize(&n.get_row_value_ref())?))
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
    pub async fn insert_many_kivs<V: Serialize>(
        &self, 
        single_prepared: &ScyllaGenericKeyIdValueTablePreparedStatements, 
        rows: &[QDatabaseKeyIdValueTableRow<V>]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(single_prepared.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.obj_id), pser::serialize(&n.value)?))
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
    pub async fn insert_many_kivs_t<V: Serialize + DeserializeOwned, R: QDatabaseKeyIdValueTableRowLike<V>>(
        &self, 
        single_prepared: &ScyllaGenericKeyIdValueTablePreparedStatements, 
        rows: &[R]
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        let mut value_list: Vec<Vec<(i64, Vec<u8>)>> = Vec::new();
        for chunk in rows.chunks(INSERT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let mut batch: Batch = Default::default();
            for _node in chunk {
                batch.append_statement(single_prepared.insert_1_statement.clone());
            }
            let values: Vec<_> = chunk
                .iter()
                .map(|n| {
                    Ok((u64_to_i64_exact(n.get_row_obj_id()), pser::serialize(&n.get_row_value_ref())?))
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
    pub async fn select_many_kiv_values<V: Serialize + DeserializeOwned>(
        &self, 
        single_prepared: &ScyllaGenericKeyIdValueTablePreparedStatements, 
        obj_ids: &[u64],
    ) -> anyhow::Result<Vec<Option<V>>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let obj_ids_i64 = obj_ids.iter().map(|id| u64_to_i64_exact(*id)).collect::<Vec<_>>();
        for chunk in obj_ids_i64.chunks(SELECT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = self.session.clone();
                    let prep = single_prepared.select_value_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key,)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Vec<u8>,)>()? {
                            match pser::deserialize::<V>(&row.0) {
                                Ok(value) => core::result::Result::<_, anyhow::Error>::Ok(Some(value)),
                                Err(e) => {
                                    tracing::error!("Deserialization error for object ID {} in {}.{}: {:?}", i64_to_u64_exact(*key), single_prepared.keyspace, single_prepared.table_name, e);
                                    Ok(None)
                                }
                            }
                        } else {
                            // Assume reverse_level = level for simplicity; adjust if tree height known
                            Ok(None)
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
    pub async fn select_many_kiv_keys_and_values<V: Serialize + DeserializeOwned, R: QDatabaseKeyIdValueTableRowCreatable<V>>(
        &self, 
        single_prepared: &ScyllaGenericKeyIdValueTablePreparedStatements, 
        obj_ids: &[u64], 
    ) -> anyhow::Result<Vec<R>> {
        let mut results = Vec::with_capacity(obj_ids.len());
        let obj_ids_i64 = obj_ids.iter().map(|id| u64_to_i64_exact(*id)).collect::<Vec<_>>();
        for chunk in obj_ids_i64.chunks(SELECT_KEY_ID_VALUE_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = self.session.clone();
                    let prep = single_prepared.select_value_obj_id_1_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, (*key,)).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(i64, Vec<u8>)>()? {
                            match pser::deserialize::<V>(&row.1) {
                                Ok(value) => core::result::Result::<_, anyhow::Error>::Ok(Some(R::create_from_key_id_value_row(i64_to_u64_exact(row.0), value))),
                                Err(e) => {
                                    tracing::error!("Deserialization error for object ID {} in {}.{}: {:?}", i64_to_u64_exact(*key), single_prepared.keyspace, single_prepared.table_name, e);
                                    Ok(None)
                                }
                            }
                        } else {
                            // Assume reverse_level = level for simplicity; adjust if tree height known
                            Ok(None)
                        }
                    }
                })
                .collect();
            let chunk_results = join_all(futures).await;
            for res in chunk_results {
                let r = res?;
                if let Some(r) = r {
                    results.push(r);
                }
            }
        }
        Ok(results)
    }


}
