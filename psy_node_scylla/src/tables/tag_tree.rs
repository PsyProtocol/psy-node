use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use futures::future::join_all;
use parth_core::{
    crypto::hash::{
        tag_tree::{hash_tag_tree_node, TagTreeMerkleProof, TagTreeNodePreimage, TagTreeStorageNode, TagTreeProofNode},
        traits::MerkleHasher,
    },
    data::{
        db::table::QDatabaseTableRoutingKey,
        hash::{merkle_node_key::SimpleMerkleNodeKey, tag_tree_node_key::TagTreeNodeWithKey},
    },
    protocol::core_types::QHashBase,
};
use scylla::{
    client::session::Session,
    statement::{batch::Batch, prepared::PreparedStatement, Statement},
};

use crate::{
    constants::{INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE, SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE},
    tables::traits::ScyllaStandardPreparedTableStatements,
    utils::{u64_to_i64_exact, u8_to_i8_exact},
};

#[derive(Clone)]
pub struct ScyllaTagTreeNodesPreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,
    pub select_1_value_statement: Statement,
    pub select_1_value_prepared: Arc<PreparedStatement>,
    pub select_1_tag_statement: Statement,
    pub select_1_tag_prepared: Arc<PreparedStatement>,
    pub select_1_value_and_tag_statement: Statement,
    pub select_1_value_and_tag_prepared: Arc<PreparedStatement>,
    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
}

impl ScyllaTagTreeNodesPreparedStatements {
    pub async fn new_from_session(session: &Session, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(&format!(
            "INSERT INTO {}.{} (unique_pending_id, level, node_index, node_value, node_tag) VALUES (?, ?, ?, ?, ?)",
            keyspace, table_name
        ));
        let insert_prepared = session.prepare(insert_1_statement.clone()).await?;
        let select_1_value_statement = Statement::new(&format!(
            "SELECT node_value FROM {}.{} WHERE unique_pending_id = ? AND level = ? AND node_index = ? LIMIT 1",
            keyspace, table_name
        ));
        let select_1_value_prepared = session.prepare(select_1_value_statement.clone()).await?;
        let select_1_tag_statement = Statement::new(&format!(
            "SELECT node_tag FROM {}.{} WHERE unique_pending_id = ? AND level = ? AND node_index = ? LIMIT 1",
            keyspace, table_name
        ));
        let select_1_tag_prepared = session.prepare(select_1_tag_statement.clone()).await?;

        let select_1_value_and_tag_statement = Statement::new(&format!(
            "SELECT node_value, node_tag FROM {}.{} WHERE unique_pending_id = ? AND level = ? AND node_index = ? LIMIT 1",
            keyspace, table_name
        ));
        let select_1_value_and_tag_prepared = session.prepare(select_1_value_and_tag_statement.clone()).await?;

        Ok(Self {
            insert_1_prepared: Arc::new(insert_prepared),
            select_1_value_prepared: Arc::new(select_1_value_prepared),
            insert_1_statement: insert_1_statement,
            select_1_value_statement: select_1_value_statement,
            select_1_tag_prepared: Arc::new(select_1_tag_prepared),
            select_1_tag_statement: select_1_tag_statement,
            select_1_value_and_tag_prepared: Arc::new(select_1_value_and_tag_prepared),
            select_1_value_and_tag_statement: select_1_value_and_tag_statement,
            keyspace: keyspace.to_string(),
            table_name: table_name.to_string(),
            table_key,
        })
    }
    pub async fn create_table(session: &Session, keyspace: &str, table_name: &str, _table_key: QDatabaseTableRoutingKey) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {}.{} (
                    unique_pending_id BIGINT,
                    level TINYINT,
                    node_index BIGINT,
                    node_value BLOB,
                    node_tag BLOB,
                    PRIMARY KEY ((unique_pending_id), level, node_index)
                ) WITH CLUSTERING ORDER BY (level ASC, node_index ASC)",
                    keyspace, table_name
                ),
                &[],
            )
            .await?;
        session.await_schema_agreement().await?;
        Ok(())
    }
    pub async fn new_create_from_session(
        session: &Session,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::create_table(&session, keyspace, table_name, table_key).await?;
        Self::new_from_session(session, keyspace, table_name, table_key).await
    }
}

#[async_trait]
impl ScyllaStandardPreparedTableStatements for ScyllaTagTreeNodesPreparedStatements {
    async fn create_table_standard(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::new_create_from_session(&session, keyspace, table_name, table_key).await
    }
}

impl ScyllaTagTreeNodesPreparedStatements {
    pub async fn set_or_insert_one(
        &self,
        session: &Session,
        unique_pending_id: u64,
        node: &SimpleMerkleNodeKey,
        tag: &[u8],
        value: &[u8],
    ) -> anyhow::Result<()> {
        session
            .execute_unpaged(
                &self.insert_1_prepared,
                (
                    u64_to_i64_exact(unique_pending_id),
                    u8_to_i8_exact(node.level),
                    u64_to_i64_exact(node.index),
                    value,
                    tag,
                ),
            )
            .await?;
        Ok(())
    }
    pub async fn get_tag_tree_node_children<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        node: &SimpleMerkleNodeKey,
        tag_tree_height: Option<u8>,
    ) -> anyhow::Result<(Hash, Hash)> {
        let real_tag_tree_height = tag_tree_height.unwrap_or(u8::MAX);
        if node.level > real_tag_tree_height {
            anyhow::bail!("Node level for node {:?} is greater than tag tree height {}", node, real_tag_tree_height);
        } else if node.level == real_tag_tree_height {
            return Ok((Hash::get_zero_value(), Hash::get_zero_value()));
        } else {
            let left_value_fut = self.select_one_tag_tree_value::<Hash>(&session, unique_pending_id, node.left_child());
            let right_value_fut = self.select_one_tag_tree_value::<Hash>(&session, unique_pending_id, node.right_child());
            let (left_value, right_value) = tokio::join!(left_value_fut, right_value_fut);
            let left_value = left_value?.unwrap_or(Hash::get_zero_value());
            let right_value = right_value?.unwrap_or(Hash::get_zero_value());
            Ok((left_value, right_value))
        }
    }
    pub async fn set_tag_only_computed<Hash: QHashBase, Hasher: MerkleHasher<Hash>>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        node: SimpleMerkleNodeKey,
        tag_tree_height: Option<u8>,
        tag: &Hash,
    ) -> anyhow::Result<()> {
        let (left_value, right_value) = self
            .get_tag_tree_node_children::<Hash>(session, unique_pending_id, &node, tag_tree_height)
            .await?;
        let new_value = hash_tag_tree_node::<Hash, Hasher>(&left_value, &right_value, &tag);
        session
            .execute_unpaged(
                &self.insert_1_prepared,
                (
                    u64_to_i64_exact(unique_pending_id),
                    u8_to_i8_exact(node.level),
                    u64_to_i64_exact(node.index),
                    new_value.to_bytes()?,
                    tag.to_bytes()?,
                ),
            )
            .await?;
        Ok(())
    }
    pub async fn set_or_insert_many<Hash: PartialEq + Copy + QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        entries: &[TagTreeNodeWithKey<Hash>],
    ) -> anyhow::Result<()> {
        let mut batch_list: Vec<Batch> = Vec::new();
        //tree_id, tree_sub_id, level, node_index, checkpoint_id, value
        let unique_pending_id_i64 = u64_to_i64_exact(unique_pending_id);
        let value_list: Vec<Vec<(i64, i8, i64, Vec<u8>, Vec<u8>)>> = entries
            .iter()
            .map(|x| {
                (
                    unique_pending_id_i64,
                    u8_to_i8_exact(x.key.level),
                    u64_to_i64_exact(x.key.index),
                    x.value.to_bytes().unwrap(),
                    x.tag.to_bytes().unwrap(),
                )
            })
            .collect::<Vec<_>>()
            .chunks(INSERT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE)
            .map(|x| x.to_vec())
            .collect();
        let chunk_lens = value_list.iter().map(|x| x.len()).collect::<Vec<_>>();
        for chunk_len in chunk_lens.into_iter() {
            let mut batch: Batch = Default::default();
            for _ in 0..chunk_len {
                batch.append_statement(self.insert_1_statement.clone());
            }

            batch_list.push(batch);
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
    pub async fn select_one_tag_tree_value<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>> {
        let res = session
            .execute_unpaged(
                &self.select_1_value_prepared,
                (
                    u64_to_i64_exact(unique_pending_id),
                    u8_to_i8_exact(key.level),
                    u64_to_i64_exact(key.index),
                ),
            )
            .await?;
        let rows = res.into_rows_result()?;
        if let Some(row) = rows.maybe_first_row::<(Option<Vec<u8>>,)>()? {
            match row.0 {
                Some(d) => Ok(Some(Hash::from_bytes(&d)?)),
                None => Ok(None),
            }
        } else {
            Ok(None)
        }
    }
    pub async fn select_one_tag_tree_value_or_zero<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        let res = session
            .execute_unpaged(
                &self.select_1_value_prepared,
                (
                    u64_to_i64_exact(unique_pending_id),
                    u8_to_i8_exact(key.level),
                    u64_to_i64_exact(key.index),
                ),
            )
            .await?;
        let rows = res.into_rows_result()?;
        if let Some(row) = rows.maybe_first_row::<(Option<Vec<u8>>,)>()? {
            match row.0 {
                Some(d) => Ok(Hash::from_bytes(&d)?),
                None => Ok(Hash::get_zero_value()),
            }
        } else {
            Ok(Hash::get_zero_value())
        }
    }
    pub async fn select_one_tag_tree_tag<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        let res = session
            .execute_unpaged(
                &self.select_1_value_and_tag_prepared,
                (
                    u64_to_i64_exact(unique_pending_id),
                    u8_to_i8_exact(key.level),
                    u64_to_i64_exact(key.index),
                ),
            )
            .await?;
        let rows = res.into_rows_result()?;
        if let Some(row) = rows.maybe_first_row::<(Option<Vec<u8>>, Option<Vec<u8>>)>()? {
            match (row.0, row.1) {
                (_, Some(tag_data)) => Ok(Hash::from_bytes(&tag_data)?),
                _ => Ok(Hash::get_zero_value()),
            }
        } else {
            Ok(Hash::get_zero_value())
        }
    }
    pub async fn select_one_tag_tree_tag_and_value<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<TagTreeStorageNode<Hash>>> {
        let res = session
            .execute_unpaged(
                &self.select_1_value_and_tag_prepared,
                (
                    u64_to_i64_exact(unique_pending_id),
                    u8_to_i8_exact(key.level),
                    u64_to_i64_exact(key.index),
                ),
            )
            .await?;
        let rows = res.into_rows_result()?;
        if let Some(row) = rows.maybe_first_row::<(Option<Vec<u8>>, Option<Vec<u8>>)>()? {
            match (row.0, row.1) {
                (Some(value_data), Some(tag_data)) => Ok(Some(TagTreeStorageNode {
                    value: Hash::from_bytes(&value_data)?,
                    tag: Hash::from_bytes(&tag_data)?,
                })),
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }
    pub async fn get_proof_node<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        sibling_key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<TagTreeProofNode<Hash>> {
        let parent_key = sibling_key.parent();
        let parent_fut = self.select_one_tag_tree_tag_and_value::<Hash>(session, unique_pending_id, &parent_key);
        let sibling_fut = self.select_one_tag_tree_value::<Hash>(session, unique_pending_id, sibling_key.to_owned());
        let (sibling, parent) = tokio::join!(sibling_fut, parent_fut);
        let sibling = sibling?.unwrap_or_default();
        let parent = parent?;
        let parent_tag = if parent.is_none() { Hash::get_zero_value() } else { parent.unwrap().tag };
        Ok(TagTreeProofNode {
            sibling: sibling,
            parent_tag,
        })
    }
    pub async fn get_proof_nodes<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        sibling_keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<TagTreeProofNode<Hash>>> {
        let futures: Vec<_> = sibling_keys
            .iter()
            .map(|sibling_key| self.get_proof_node::<Hash>(session, unique_pending_id, sibling_key))
            .collect();
        let results = join_all(futures).await;
        let mut proof_nodes = Vec::with_capacity(results.len());
        for res in results {
            proof_nodes.push(res?);
        }
        Ok(proof_nodes)
    }
    pub async fn get_tag_tree_node_preimage<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        tag_tree_height: Option<u8>,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<TagTreeNodePreimage<Hash>> {
        if key.level > tag_tree_height.unwrap_or(u8::MAX) {
            anyhow::bail!("Node level for node {:?} is greater than tag tree height {:?}", key, tag_tree_height);
        }
        let lr_child_fut = self.get_tag_tree_node_children::<Hash>(session, unique_pending_id, key, tag_tree_height);
        let node_tag_fut = self.select_one_tag_tree_tag::<Hash>(session, unique_pending_id, key);
        let (lr_child, node_tag) = tokio::join!(lr_child_fut, node_tag_fut);
        let (left, right) = lr_child?;
        let node_tag = node_tag?;

        Ok(TagTreeNodePreimage { left, right, tag: node_tag })
    }
    pub async fn select_tag_tree_proof<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<TagTreeMerkleProof<Hash>> {
        let mut sibling_keys = key.siblings();
        let mut parent_keys = sibling_keys.iter().map(|s| s.parent()).collect::<Vec<_>>();
        let left_value_key = key.left_child();
        let right_value_key = key.right_child();
        sibling_keys.push(left_value_key);
        sibling_keys.push(right_value_key);
        sibling_keys.push(SimpleMerkleNodeKey::new_root());

        parent_keys.push(key);
        let tags_fut = self.select_many_tag_tree_tags_or_zero::<Hash>(session, unique_pending_id, &parent_keys);
        let needed_values = self.select_many_tag_tree_values_or_zero::<Hash>(session, unique_pending_id, &sibling_keys);
        let (tags, values) = tokio::join!(tags_fut, needed_values);
        let mut tags = tags?;
        let mut values = values?;

        let root_value = values.pop().unwrap();
        let right_value = values.pop().unwrap();
        let left_value = values.pop().unwrap();
        let self_tag = tags.pop().unwrap();
        let preimage = TagTreeNodePreimage {
            left: left_value,
            right: right_value,
            tag: self_tag,
        };
        let proof_nodes = values
            .into_iter()
            .zip(tags.into_iter())
            .map(|(sibling, parent_tag)| TagTreeProofNode { sibling, parent_tag })
            .collect::<Vec<_>>();

        Ok(TagTreeMerkleProof {
            index: key.index,
            leaf: preimage,
            root: root_value,
            siblings: proof_nodes,
        })
    }
    pub async fn select_tag_tree_proof_old<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<TagTreeMerkleProof<Hash>> {
        let sibling_keys = key.siblings();
        let sibling_proof_nodes_fut = self.get_proof_nodes::<Hash>(&session, unique_pending_id, &sibling_keys);
        let root_fut = self.select_one_tag_tree_value::<Hash>(&session, unique_pending_id, SimpleMerkleNodeKey::new_root());
        let leaf_fut = self.get_tag_tree_node_preimage::<Hash>(&session, unique_pending_id, None, &key);
        let (sibling_proof_nodes, root, leaf) = tokio::join!(sibling_proof_nodes_fut, root_fut, leaf_fut);
        let sibling_proof_nodes = sibling_proof_nodes?;
        let root = root?;
        if root.is_none() {
            anyhow::bail!("Tag tree proof generation failed: missing root value");
        }
        let root = root.unwrap();
        let leaf = leaf?;

        Ok(TagTreeMerkleProof {
            index: key.index,
            leaf,
            root,
            siblings: sibling_proof_nodes,
        })

        /*
        let sibling_keys = key.siblings();
        let parent_keys = sibling_keys.iter().map(|s| s.parent()).collect::<Vec<_>>();
        let left_value_key = key.left_child();
        let right_value_key = key.right_child();
        let dist_from_root = key.level as usize;

        let sibling_values_fut = self.select_many_tag_tree_values::<Hash>(&session, unique_pending_id, &sibling_keys);
        let parent_tags_fut = self.select_many_tag_tree_tags::<Hash>(&session, unique_pending_id, &parent_keys);
        let left_value_fut = self.select_one_tag_tree_value::<Hash>(&session, unique_pending_id, left_value_key);
        let right_value_fut = self.select_one_tag_tree_value::<Hash>(&session, unique_pending_id, right_value_key);
        let self_tag_value_fut = self.select_one_tag_tree_tag_and_value::<Hash>(&session, unique_pending_id, &key);
        let root_key = SimpleMerkleNodeKey::new(0,0);
        let root_value_fut = self.select_one_tag_tree_value::<Hash>(&session, unique_pending_id, root_key);
        let (sibling_values, parent_tags, left_value, right_value, self_value_tag, root_value) = tokio::join!(sibling_values_fut, parent_tags_fut, left_value_fut, right_value_fut, self_tag_value_fut, root_value_fut);
        let sibling_values = sibling_values?.into_iter().flatten().collect::<Vec<_>>();
        if sibling_values.len() != dist_from_root {
            anyhow::bail!("Tag tree proof generation failed: expected {} sibling values, got {}",
                dist_from_root,
                sibling_values.len()
            );
        }
        let root_value = root_value?;
        if root_value.is_none() {
            anyhow::bail!("Tag tree proof generation failed: missing root value");
        }
        let root_value = root_value.unwrap();
        let parent_tags = parent_tags?.into_iter().flatten().collect::<Vec<_>>();
        if parent_tags.len() != dist_from_root {
            anyhow::bail!("Tag tree proof generation failed: expected {} parent tags, got {}",
                dist_from_root,
                parent_tags.len()
            );
        }

        let left_value = left_value?;
        let right_value = right_value?;
        let self_value_tag = self_value_tag?;
        if self_value_tag.is_none() {
            anyhow::bail!("Tag tree proof generation failed: missing self value/tag at key {:?}", key);
        }
        let self_value_tag = self_value_tag.unwrap();

        let preimage = TagTreeNodePreimage {
            left: left_value.unwrap_or_default(),
            right: right_value.unwrap_or_default(),
            tag: self_value_tag.tag,
        };

        let proof = TagTreeMerkleProof {
            index: key.index,
            leaf: preimage,
            root: root_value,
            siblings: sibling_values.iter().zip(parent_tags.iter()).map(|(sibling, parent_tag)| TagTreeProofNode {
                sibling: *sibling,
                parent_tag: *parent_tag,
            }).collect(),
        };

        Ok(proof)
        */
    }

    pub async fn select_many_tag_tree_tags_and_values<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<TagTreeStorageNode<Hash>>>> {
        let mut results = Vec::with_capacity(keys.len());
        let unique_pending_id_i64 = u64_to_i64_exact(unique_pending_id);
        let keys_i64 = keys
            .iter()
            .map(|key| (unique_pending_id_i64, u8_to_i8_exact(key.level), u64_to_i64_exact(key.index)))
            .collect::<Vec<_>>();
        for chunk in keys_i64.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = &session;
                    let prep = self.select_1_value_and_tag_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, *key).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Option<Vec<u8>>, Option<Vec<u8>>)>()? {
                            match (row.0, row.1) {
                                (Some(value_data), Some(tag_data)) => anyhow::Ok(Some(TagTreeStorageNode {
                                    value: Hash::from_bytes(&value_data)?,
                                    tag: Hash::from_bytes(&tag_data)?,
                                })),
                                _ => Ok(None),
                            }
                        } else {
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

    pub async fn select_many_tag_tree_tags_or_zero<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        let mut results = Vec::with_capacity(keys.len());
        let unique_pending_id_i64 = u64_to_i64_exact(unique_pending_id);
        let keys_i64 = keys
            .iter()
            .map(|key| (unique_pending_id_i64, u8_to_i8_exact(key.level), u64_to_i64_exact(key.index)))
            .collect::<Vec<_>>();
        for chunk in keys_i64.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = &session;
                    let prep = self.select_1_value_and_tag_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, *key).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Option<Vec<u8>>, Option<Vec<u8>>)>()? {
                            match row.1 {
                                Some(tag_data) => anyhow::Ok(Hash::from_bytes(&tag_data)?),
                                _ => anyhow::Ok(Hash::get_zero_value()),
                            }
                        } else {
                            anyhow::Ok(Hash::get_zero_value())
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
    pub async fn select_many_tag_tree_tags_and_values_or_zero<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<TagTreeStorageNode<Hash>>> {
        let mut results = Vec::with_capacity(keys.len());
        let unique_pending_id_i64 = u64_to_i64_exact(unique_pending_id);
        let keys_i64 = keys
            .iter()
            .map(|key| (unique_pending_id_i64, u8_to_i8_exact(key.level), u64_to_i64_exact(key.index)))
            .collect::<Vec<_>>();
        for chunk in keys_i64.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = &session;
                    let prep = self.select_1_value_and_tag_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, *key).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Option<Vec<u8>>, Option<Vec<u8>>)>()? {
                            match (row.0, row.1) {
                                (Some(value_data), Some(tag_data)) => anyhow::Ok(TagTreeStorageNode {
                                    value: Hash::from_bytes(&value_data)?,
                                    tag: Hash::from_bytes(&tag_data)?,
                                }),
                                _ => Ok(TagTreeStorageNode {
                                    value: Hash::get_zero_value(),
                                    tag: Hash::get_zero_value(),
                                }),
                            }
                        } else {
                            Ok(TagTreeStorageNode {
                                value: Hash::get_zero_value(),
                                tag: Hash::get_zero_value(),
                            })
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

    pub async fn select_many_tag_tree_values<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<Hash>>> {
        let mut results = Vec::with_capacity(keys.len());
        let unique_pending_id_i64 = u64_to_i64_exact(unique_pending_id);
        let keys_i64 = keys
            .iter()
            .map(|key| (unique_pending_id_i64, u8_to_i8_exact(key.level), u64_to_i64_exact(key.index)))
            .collect::<Vec<_>>();
        for chunk in keys_i64.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = &session;
                    let prep = self.select_1_value_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, *key).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Option<Vec<u8>>,)>()? {
                            match row.0 {
                                Some(data) => anyhow::Ok(Some(Hash::from_bytes(&data)?)),
                                None => Ok(None),
                            }
                        } else {
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
    pub async fn select_many_tag_tree_values_or_zero<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        let mut results = Vec::with_capacity(keys.len());
        let unique_pending_id_i64 = u64_to_i64_exact(unique_pending_id);
        let keys_i64 = keys
            .iter()
            .map(|key| (unique_pending_id_i64, u8_to_i8_exact(key.level), u64_to_i64_exact(key.index)))
            .collect::<Vec<_>>();
        for chunk in keys_i64.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = &session;
                    let prep = self.select_1_value_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, *key).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Option<Vec<u8>>,)>()? {
                            match row.0 {
                                Some(data) => anyhow::Ok(Hash::from_bytes(&data)?),
                                None => Ok(Hash::get_zero_value()),
                            }
                        } else {
                            Ok(Hash::get_zero_value())
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

    pub async fn select_many_tag_tree_tags<Hash: QHashBase>(
        &self,
        session: &Session,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<Hash>>> {
        let mut results = Vec::with_capacity(keys.len());
        let unique_pending_id_i64 = u64_to_i64_exact(unique_pending_id);
        let keys_i64 = keys
            .iter()
            .map(|key| (unique_pending_id_i64, u8_to_i8_exact(key.level), u64_to_i64_exact(key.index)))
            .collect::<Vec<_>>();
        for chunk in keys_i64.chunks(SELECT_SINGLE_ID_CHECKPOINTED_OBJECT_BATCH_SIZE) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|key| {
                    let session = &session;
                    let prep = self.select_1_tag_prepared.clone();
                    async move {
                        let res = session.execute_unpaged(&prep, *key).await?;
                        let rows = res.into_rows_result()?;
                        if let Some(row) = rows.maybe_first_row::<(Option<Vec<u8>>,)>()? {
                            match row.0 {
                                Some(data) => anyhow::Ok(Some(Hash::from_bytes(&data)?)),
                                None => Ok(None),
                            }
                        } else {
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
}
