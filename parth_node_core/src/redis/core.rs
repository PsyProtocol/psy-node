use std::{num::NonZeroUsize, time::Duration};
use pser::{QBytesSerialize, QBytesDeserialize};

use auto_impl::auto_impl;
use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use parth_core::{crypto::hash::tag_tree::TagTreeNodeStorage, data::{hash::{merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}, tag_tree_node_key::TagTreeNodeKey}, serializable::{QPDPair, QPDSerializable}}, protocol::core_types::QHashBase, store::{job_manager::QJobManagerConfig, nmq::{NMQBasicSubscriber, NMQPublisher, NMQQueueWaiter}, tag_tree_store::{GenericTagTreeTempStoreDumper, GenericTagTreeTempStoreReader, GenericTagTreeTempStoreWriter}, temporary_store::{QPTemporaryStoreReader, QPTemporaryStoreWriter}}};
use redis::AsyncCommands;

use async_trait::async_trait;
use tokio::time::sleep;

use crate::redis::constants::{JOB_MANAGER_COMPLETED_JOBS_STORE_PREFIX, JOB_MANAGER_COMPLETED_TASK_GROUPS_QUEUE_PREFIX, JOB_MANAGER_PENDING_JOBS_QUEUE_PREFIX, JOB_MANAGER_RETRY_JOBS_QUEUE_PREFIX, JOB_MANAGER_TASK_GROUPS_SET_PREFIX, JOB_MANAGER_TASK_GROUP_COUNTER_PREFIX, PROOF_STORE_COUNTERS_PREFIX_1, PROOF_STORE_KEY_PREFIX_1, PS_NOTIFICATIONS_QUEUE_KEY_PREFIX, TAG_TREE_TEMP_QUEUE_PREFIX, TAG_TREE_TEMP_STORE_PREFIX};
// Re-use constants from fred_queue

pub const REALM_PENDING_USER_QUEUE_KEY_PREFIX: &'static str = "RMPUQ";
pub const MAX_CHECKPOINT_COUNT: usize = 256;

#[auto_impl(&, Box, Arc)]
pub trait BizKey {
    fn biz_key(&self) -> String;
}


pub trait QueuePrefixKey {
    fn worker_queue_key(&self) -> String;
    fn notifications_queue_key(&self) -> String;
    fn temporary_data_store_key(&self) -> String;
    fn temporary_counter_store_key(&self) -> String;
    fn temporary_tag_tree_key(&self, tree_id: u32, checkpoint_uuid: u128) -> String;
    fn temporary_tag_tree_queue_key(&self, tree_id: u32, checkpoint_uuid: u128, partition: u32) -> String;
    fn job_manager_pending_jobs_queue_key(&self, realm_id: u64, channel_id: u128, task_group_id: u64) -> String;
    fn job_manager_retry_jobs_queue_key(&self, realm_id: u64, channel_id: u128, task_group_id: u64) -> String;
    fn job_manager_completed_jobs_store_key(&self, realm_id: u64, channel_id: u128) -> String;
    fn job_manager_task_groups_set_key(&self, realm_id: u64, channel_id: u128) -> String;
    fn job_manager_task_group_counter_key(&self, realm_id: u64, channel_id: u128, task_group_id: u64) -> String;
    fn job_manager_completed_tasks_group_queue_key(&self, realm_id: u64, channel_id: u128, task_group_id: u64) -> String;

}
#[derive(Debug, Clone)]
pub struct ProofStoreRedisAsync {
    pub pool: Pool<RedisConnectionManager>,
    biz_key: String,
    realm_id: u64,
    realm_sub_id: u64,
    pub job_manager_config: QJobManagerConfig,
}

impl BizKey for ProofStoreRedisAsync {
    fn biz_key(&self) -> String {
        self.biz_key.clone()
    }
}
impl QueuePrefixKey for ProofStoreRedisAsync {
    fn worker_queue_key(&self) -> String {
        format!(
            "{}-{}-{}-{}",
            PROOF_STORE_KEY_PREFIX_1, self.biz_key(), self.realm_id, self.realm_sub_id
        )
    }
    fn notifications_queue_key(&self) -> String {
        format!(
            "{}-{}-{}-{}",
            PS_NOTIFICATIONS_QUEUE_KEY_PREFIX, self.biz_key(), self.realm_id, self.realm_sub_id
        )
    }
    fn temporary_data_store_key(&self) -> String {
        format!(
            "{}-{}-{}-{}",
            PROOF_STORE_KEY_PREFIX_1, self.biz_key(), self.realm_id, self.realm_sub_id
        )
    }
    fn temporary_counter_store_key(&self) -> String {
        format!(
            "{}-{}-{}-{}",
            PROOF_STORE_COUNTERS_PREFIX_1, self.biz_key(), self.realm_id, self.realm_sub_id
        )
    }
    
    fn temporary_tag_tree_key(&self, tree_id: u32, checkpoint_uuid: u128) -> String {
        format!(
            "{}-{}-{}-{}-{}-{}",
            TAG_TREE_TEMP_STORE_PREFIX, self.biz_key(), self.realm_id, self.realm_sub_id, tree_id, checkpoint_uuid
        )
    }
    fn temporary_tag_tree_queue_key(&self, tree_id: u32, checkpoint_uuid: u128, partition: u32) -> String {
        format!(
            "{}-{}-{}-{}-{}-{}-{}",
            TAG_TREE_TEMP_QUEUE_PREFIX, self.biz_key(), self.realm_id, self.realm_sub_id, tree_id, checkpoint_uuid, partition
        )
    }
    
    fn job_manager_pending_jobs_queue_key(&self, realm_id: u64, channel_id: u128, task_group_id: u64) -> String {
        format!(
            "{}-{}-{}-{}-{}",
            JOB_MANAGER_PENDING_JOBS_QUEUE_PREFIX, self.biz_key(), realm_id, channel_id, task_group_id
        )
    }
    
    fn job_manager_retry_jobs_queue_key(&self, realm_id: u64, channel_id: u128, task_group_id: u64) -> String {
        format!(
            "{}-{}-{}-{}-{}",
            JOB_MANAGER_RETRY_JOBS_QUEUE_PREFIX, self.biz_key(), realm_id, channel_id, task_group_id
        )
    }
    
    fn job_manager_completed_jobs_store_key(&self, realm_id: u64, channel_id: u128) -> String {
        format!(
            "{}-{}-{}-{}",
            JOB_MANAGER_COMPLETED_JOBS_STORE_PREFIX, self.biz_key(), realm_id, channel_id
        )
    }
    
    fn job_manager_task_groups_set_key(&self, realm_id: u64, channel_id: u128) -> String {
        format!(
            "{}-{}-{}-{}",
            JOB_MANAGER_TASK_GROUPS_SET_PREFIX, self.biz_key(), realm_id, channel_id
        )
    }
    
    fn job_manager_task_group_counter_key(&self, realm_id: u64, channel_id: u128, task_group_id: u64) -> String {
        format!(
            "{}-{}-{}-{}-{}",
            JOB_MANAGER_TASK_GROUP_COUNTER_PREFIX, self.biz_key(), realm_id, channel_id, task_group_id
        )
    }
    
    fn job_manager_completed_tasks_group_queue_key(&self, realm_id: u64, channel_id: u128, task_group_id: u64) -> String {
        format!(
            "{}-{}-{}-{}-{}",
            JOB_MANAGER_COMPLETED_TASK_GROUPS_QUEUE_PREFIX, self.biz_key(), realm_id, channel_id, task_group_id
        )
    }
}

impl ProofStoreRedisAsync {
    pub async fn new(
        pool: Pool<RedisConnectionManager>,
        biz_key: String,
        realm_id: u64,
        realm_sub_id: u64,
        job_manager_config: QJobManagerConfig,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            pool,
            biz_key: biz_key,
            realm_id,
            realm_sub_id,
            job_manager_config,
        })
    }
    pub fn pool(&self) -> &Pool<RedisConnectionManager> {
        &self.pool
    }
    pub async fn get_bytes_generic(&self, ns_key: &str, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut con = self.pool.get().await?;
        let data: Vec<u8> = con.hget(ns_key, key).await?;
        Ok(data)
    }
    pub async fn get_iu64_generic(&self, ns_key: &str, key: &[u8]) -> anyhow::Result<u64> {
        let mut con = self.pool.get().await?;
        let data: Vec<u8> = con.hget(ns_key, key).await?;
        if data.len() == 8 {
            let mut array = [0u8; 8];
            array.copy_from_slice(&data);
            let value = i64::from_le_bytes(array);
            if value < 0 {
                Ok(0)
            }else{
                Ok(value as u64)
            }
        } else {
            Ok(0)
        }
    }

    pub async fn set_bytes_generic(&self, ns_key: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.hset(ns_key, key, value).await?;
        Ok(())
    }
    pub async fn set_iu64_generic(&self, ns_key: &str, key: &[u8], value: i64) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.hset(ns_key, key, &value.to_le_bytes()[..]).await?;
        Ok(())
    }

    pub async fn inc_iu64_generic(&self, ns_key: &str, key: &[u8], amount: i64) -> anyhow::Result<u64> {
        let mut con = self.pool.get().await?;
        let new_value: u64 = con.hincr(ns_key, key, amount).await?;
        Ok(new_value)
    }

    pub async fn add_to_set_generic(&self, ns_key: &str, member: &[u8]) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.sadd(ns_key, member).await?;
        Ok(())
    }
    async fn remove_from_set_generic(&self, ns_key: &str, member: &[u8]) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.srem(ns_key, member).await?;
        Ok(())
    }
    pub async fn get_set_generic(&self, ns_key: &str) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut con = self.pool.get().await?;
        let members: Vec<Vec<u8>> = con.smembers(ns_key).await?;
        Ok(members)
    }
    pub async fn add_to_set_u64(&self, ns_key: &str, member: u64) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.sadd(ns_key, member).await?;
        Ok(())
    }
    pub async fn remove_from_set_u64(&self, ns_key: &str, member: u64) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.srem(ns_key, member).await?;
        Ok(())
    }
    pub async fn get_set_u64(&self, ns_key: &str) -> anyhow::Result<Vec<u64>> {
        let mut con = self.pool.get().await?;
        let members: Vec<u64> = con.smembers(ns_key).await?;
        Ok(members)
    }

    pub async fn push_to_generic_u64_queue(&self, queue_key: &str, item: u64) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.rpush(queue_key, item).await?;
        Ok(())
    }
    pub async fn wait_for_generic_u64_queue(&self, queue_key: &str) -> anyhow::Result<u64> {
        let mut con = self.pool.get().await?;
        loop {
            let item: Option<u64> = con.lpop(queue_key, NonZeroUsize::new(1)).await?;
            if let Some(i) = item {
                return Ok(i);
            } else {
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
    pub async fn push_to_generic_obj_queue<T: QPDSerializable>(&self, queue_key: &str, item: &T) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.rpush(queue_key, item.to_bytes()?).await?;
        Ok(())
    }
    pub async fn push_many_to_generic_obj_queue<T: QPDSerializable>(&self, queue_key: &str, items: &[T]) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let items: Vec<Vec<u8>> = items.iter().map(|x| x.to_bytes()).collect::<anyhow::Result<_>>()?;

        let _: () = con.rpush(queue_key, items).await?;
        Ok(())
    }
    pub async fn pop_from_generic_obj_queue_or_none<T: QPDSerializable>(&self, queue_key: &str) -> anyhow::Result<Option<T>> {
        let mut con = self.pool.get().await?;
        let item: Option<Vec<u8>> = con.lpop(queue_key, NonZeroUsize::new(1)).await?;
        if let Some(i) = item {
            Ok(Some(T::from_bytes(&i)?))
        } else {
            Ok(None)
        }
    }
    pub async fn wait_for_generic_obj_queue<T: QPDSerializable>(&self, queue_key: &str) -> anyhow::Result<T> {
        let mut con = self.pool.get().await?;
        loop {
            let item: Option<Vec<u8>> = con.lpop(queue_key, NonZeroUsize::new(1)).await?;
            if let Some(i) = item {
                return Ok(T::from_bytes(&i)?);
            } else {
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
    pub async fn dump_ro_generic_obj_queue<T: QPDSerializable>(&self, queue_key: &str) -> anyhow::Result<Vec<T>> {
        let mut con = self.pool.get().await?;
        let items: Vec<Vec<u8>> = con.lrange(queue_key, 0, -1).await?;
        let result: Vec<T> = items.into_iter().map(|x| T::from_bytes(&x)).collect::<anyhow::Result<_>>()?;
        Ok(result)
    }
}

#[async_trait]
impl QPTemporaryStoreReader for ProofStoreRedisAsync {

    async fn contains_key(&self, key: &[u8]) -> anyhow::Result<bool> {
        let ns_key = self.temporary_data_store_key();
        let mut con = self.pool.get().await?;
        let exists: bool = con.hget(&ns_key, key).await?;
        Ok(exists)
    }

    async fn get_bytes(&self, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        let ns_key = self.temporary_data_store_key();
        let mut con = self.pool.get().await?;
        let data: Vec<u8> = con.hget(&ns_key, key).await?;
        Ok(data)
    }

    async fn get_bytes_batch(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>> {
        let ns_key = self.temporary_data_store_key();

        let mut con = self.pool.get().await?;
        let data: Vec<Vec<u8>> = con.hget(&ns_key, keys).await?;
        Ok(data)
    }

    async fn get_counter_by_key(&self, key: &[u8]) -> anyhow::Result<u64> {
        let ns_key = self.temporary_counter_store_key();
        let mut con = self.pool.get().await?;
        let counter: u64 = con.hget(&ns_key, key).await?;
        Ok(counter)
    }

}

#[async_trait]
impl QPTemporaryStoreWriter for ProofStoreRedisAsync {

    async fn delete_key(&self, key: &[u8]) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.hget_del(&self.temporary_data_store_key(), key).await?;
        Ok(())
    }
    async fn set_bytes(&self, key: Vec<u8>, value: Vec<u8>) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.hset(&self.temporary_data_store_key(), key, value).await?;
        Ok(())
    }
    async fn set_bytes_ref(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.hset(&self.temporary_data_store_key(), key, value).await?;
        Ok(())
    }
    async fn set_bytes_batch(&self, items: Vec<QPDPair<Vec<u8>, Vec<u8>>>) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.hset_multiple(&self.temporary_data_store_key(), &items.into_iter().map(|x| (x.key, x.value)).collect::<Vec<_>>()).await?;
        Ok(())
    }
    async fn set_counter_by_key(&self, key: &[u8], value: u64) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.hset(&self.temporary_counter_store_key(), key, value).await?;
        Ok(())
    }
    async fn inc_counter_by_key(&self, key: &[u8]) -> anyhow::Result<u64> {
        let mut con = self.pool.get().await?;
        let new_value: u64 = con.hincr(&self.temporary_counter_store_key(), key, 1).await?;
        Ok(new_value)
    }

}


#[async_trait]
impl NMQPublisher for ProofStoreRedisAsync {
    async fn enqueue_message_to_queue(&self, realm_id: u64, queue_type: u16, channel_id: u128, variant: u64, message: Vec<u8>) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let queue_key = format!("{}-{}-{}-{}-{}-{}", REALM_PENDING_USER_QUEUE_KEY_PREFIX, self.biz_key(), realm_id, queue_type, channel_id, variant);
        let _: () = con.rpush(queue_key, message).await?;
        Ok(())
    }
    async fn enqueue_messages_to_queue(&self, realm_id: u64, queue_type: u16, channel_id: u128, variant: u64, messages: Vec<Vec<u8>>) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let queue_key = format!("{}-{}-{}-{}-{}-{}", REALM_PENDING_USER_QUEUE_KEY_PREFIX, self.biz_key(), realm_id, queue_type, channel_id, variant);
        let _: () = con.rpush(queue_key, messages).await?;
        Ok(())
    }
}


#[async_trait]
impl NMQBasicSubscriber for ProofStoreRedisAsync {
    async fn dequeue_message_from_queue(&self, realm_id: u64, queue_type: u16, channel_id: u128, variant: u64) -> anyhow::Result<Vec<u8>> {
        let mut con = self.pool.get().await?;
        let queue_key = format!("{}-{}-{}-{}-{}-{}", REALM_PENDING_USER_QUEUE_KEY_PREFIX, self.biz_key(), realm_id, queue_type, channel_id, variant);
        let message: Vec<u8> = con.lpop(queue_key, NonZeroUsize::new(1)).await?;
        Ok(message)
    }
    async fn dump_messages_from_queue(&self, realm_id: u64, queue_type: u16, channel_id: u128, variant: u64) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut con = self.pool.get().await?;
        let queue_key = format!("{}-{}-{}-{}-{}-{}", REALM_PENDING_USER_QUEUE_KEY_PREFIX, self.biz_key(), realm_id, queue_type, channel_id, variant);
        let messages: Vec<Vec<u8>> = con.lrange(queue_key.clone(), 0, -1).await?;
        let _: () = con.del(queue_key).await?;
        Ok(messages)
    }
}

#[async_trait]
impl NMQQueueWaiter for ProofStoreRedisAsync {
    async fn wait_for_message_in_queue(&self, realm_id: u64, queue_type: u16, channel_id: u128, variant: u64, _timeout_ms: u64) -> anyhow::Result<Vec<u8>>{
        let queue_key = format!("{}-{}-{}-{}-{}-{}", REALM_PENDING_USER_QUEUE_KEY_PREFIX, self.biz_key(), realm_id, queue_type, channel_id, variant);
        loop {
            let mut con = self.pool.get().await?;
            let job_res: Option<Vec<u8>> = con.lpop(&queue_key, None).await?;
            match job_res {
                Some(g) => {
                    if g.len() != 0 {
                        return Ok(g);
                    }
                }
                None => {}
            };
            sleep(Duration::from_millis(100)).await;
        }
    }
}
#[async_trait]
impl<Hash: QHashBase> GenericTagTreeTempStoreReader<Hash> for ProofStoreRedisAsync {
    async fn get_node_at_unique_checkpoint_temp(&self, tree_id: u32, unique_checkpoint_id: u128, level: u8, index: u64) -> anyhow::Result<TagTreeNodeStorage<Hash>>{
        let ns_key = self.temporary_tag_tree_key(tree_id, unique_checkpoint_id);
        let mut con = self.pool.get().await?;
        let key = TagTreeNodeKey { tag_tree_id: tree_id, key: SimpleMerkleNodeKey { level, index } };

        let res: Vec<u8> = con.hget(&ns_key, &key.to_bytes()?).await?;
        if res.len() == 0 {
            anyhow::bail!("node not found");
        }
        Ok(TagTreeNodeStorage::<Hash>::from_bytes(&res)?)
    }
    async fn get_nodes_at_unique_checkpoint_temp(&self, tree_id: u32, unique_checkpoint_id: u128, nodes: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<TagTreeNodeStorage<Hash>>>{
        let ns_key = self.temporary_tag_tree_key(tree_id, unique_checkpoint_id);

        let mut con = self.pool.get().await?;
        let mut result = Vec::new();
        for node in nodes {
            let key = TagTreeNodeKey { tag_tree_id: tree_id, key: *node };
            let res: Vec<u8> = con.hget(&ns_key, &key.to_bytes()?).await?;
            if res.len() == 0 {
                anyhow::bail!("node not found");
            }
            result.push(TagTreeNodeStorage::<Hash>::from_bytes(&res)?);
        }
        Ok(result)
    }

}


#[async_trait]
impl<Hash: QHashBase> GenericTagTreeTempStoreWriter<Hash> for ProofStoreRedisAsync {
    async fn put_nodes_for_checkpoint(&self, tree_id: u32, unique_checkpoint_id: u128, nodes: &[SimpleMerkleNode<TagTreeNodeStorage<Hash>>]) -> anyhow::Result<()>{
        let ns_key = self.temporary_tag_tree_key(tree_id, unique_checkpoint_id);
        let mut con = self.pool.get().await?;
        for node in nodes {
            let key = TagTreeNodeKey { tag_tree_id: tree_id, key: node.key };
            con.hset::<_, _, _, ()>(&ns_key, &key.to_bytes()?, &node.value.to_bytes()?).await?;
        }
        Ok(())
    }
    async fn push_node_to_unique_checkpoint_temp(&self, tree_id: u32, unique_checkpoint_id: u128, partition: u32, node: &SimpleMerkleNode<TagTreeNodeStorage<Hash>>) -> anyhow::Result<()>{
        let ns_key = self.temporary_tag_tree_queue_key(tree_id, unique_checkpoint_id, partition);
        let mut con = self.pool.get().await?;
        // push to array
        let _: () = con.rpush(&ns_key, node.to_qbytes()?).await?;
        Ok(())
    }
}


#[async_trait]
impl<Hash: QHashBase> GenericTagTreeTempStoreDumper<Hash> for ProofStoreRedisAsync {
        async fn dump_nodes_for_unique_checkpoint_tmp(&self, tree_id: u32, unique_checkpoint_id: u128, partition: u32) -> anyhow::Result<Vec<SimpleMerkleNode<TagTreeNodeStorage<Hash>>>>{
            let ns_key = self.temporary_tag_tree_queue_key(tree_id, unique_checkpoint_id, partition);
            let mut con = self.pool.get().await?;
            let data: Vec<Vec<u8>> = con.lrange(&ns_key, 0, -1).await?;
            let mut result = Vec::new();
            for d in data {
                result.push(SimpleMerkleNode::<TagTreeNodeStorage<Hash>>::from_qbytes(&d)?);
            }
            let _: () = con.del(ns_key).await?;
            Ok(result)
        }
}