use async_trait::async_trait;
use std::{num::NonZeroUsize, time::Duration};

use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use parth_common_v0::data::serializable::{QPDPair, QPDSerializable};
use redis::AsyncCommands;
use tokio::time::sleep;

use crate::store::traits::tmp_db::{QPBasicStoreKVReader, QPBasicStoreKVWriter, QPEphemeralQueueType, QPTempQueueEmphemeralPublisher, QPTempQueueEmphemeralSubscriber, QPTempStoreKVU64Reader, QPTempStoreKVU64Writer};
pub const REDIS_TMP_EPHEMERAL_QUEUE_PREFIX: &str = "TEMOV1";
pub const REDIS_TMP_KV_STORE_PREFIX: &str = "TKVSV1";
fn get_ephemeral_queue_ns_key(biz_key: &str, realm_id: u64, realm_sub_id: u64, queue_type: u32, unique_id: u128) -> String {
    format!("{}-{}-{}-{}-{}-{}", REDIS_TMP_EPHEMERAL_QUEUE_PREFIX, biz_key, realm_id, realm_sub_id, queue_type, unique_id)
}
fn get_tmp_kv_store_ns_key(biz_key: &str, realm_id: u64, realm_sub_id: u64, table_type: u32) -> String {
    format!("{}-{}-{}-{}-{}", REDIS_TMP_KV_STORE_PREFIX, biz_key, realm_id, realm_sub_id, table_type)
}

#[derive(Debug, Clone)]
pub struct ProofStoreRedisAsync {
    pub pool: Pool<RedisConnectionManager>,
    biz_key: String,
    realm_id: u64,
    realm_sub_id: u64,
}


impl ProofStoreRedisAsync {
    pub fn new(
        pool: Pool<RedisConnectionManager>,
        biz_key: String,
        realm_id: u64,
        realm_sub_id: u64,
    ) -> Self {
        Self {
            pool,
            biz_key,
            realm_id,
            realm_sub_id,
        }
    }
    pub fn get_kv_store_key(&self, table_type: u32) -> String {
        get_tmp_kv_store_ns_key(&self.biz_key, self.realm_id, self.realm_sub_id, table_type)
    }
    pub fn get_ephemeral_queue_key(&self, queue_type: u32, unique_id: u128) -> String {
        get_ephemeral_queue_ns_key(&self.biz_key, self.realm_id, self.realm_sub_id, queue_type, unique_id)
    }
    pub fn pool(&self) -> &Pool<RedisConnectionManager> {
        &self.pool
    }

    pub async fn get_bytes_generic_internal(&self, ns_key: &str, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut con = self.pool.get().await?;
        let data: Vec<u8> = con.hget(ns_key, key).await?;
        Ok(data)
    }
    pub async fn get_many_bytes_generic_internal(&self, ns_key: &str, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut con = self.pool.get().await?;
        let data: Vec<Vec<u8>> = con.hget(ns_key, keys).await?;
        Ok(data)
    }

    pub async fn set_bytes_generic_internal(&self, ns_key: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.hset(ns_key, key, value).await?;
        Ok(())
    }
    pub async fn set_many_bytes_generic_internal(&self, ns_key: &str, items: Vec<QPDPair<Vec<u8>, Vec<u8>>>) -> anyhow::Result<()> {

        let mut con = self.pool.get().await?;
        let _: () = con.hset_multiple(ns_key, &items.into_iter().map(|x| (x.key, x.value)).collect::<Vec<_>>()).await?;
        Ok(())
    }
    pub async fn get_iu64_generic_internal(&self, ns_key: &str, key: &[u8]) -> anyhow::Result<u64> {
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
    pub async fn set_iu64_generic_internal(&self, ns_key: &str, key: &[u8], value: i64) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.hset(ns_key, key, &value.to_le_bytes()[..]).await?;
        Ok(())
    }

    pub async fn inc_iu64_generic_internal(&self, ns_key: &str, key: &[u8], amount: i64) -> anyhow::Result<u64> {
        let mut con = self.pool.get().await?;
        let new_value: u64 = con.hincr(ns_key, key, amount).await?;
        Ok(new_value)
    }

    pub async fn add_to_set_generic_internal(&self, ns_key: &str, member: &[u8]) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.sadd(ns_key, member).await?;
        Ok(())
    }
    pub async fn remove_from_set_generic_internal(&self, ns_key: &str, member: &[u8]) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.srem(ns_key, member).await?;
        Ok(())
    }
    pub async fn get_set_generic_internal(&self, ns_key: &str) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut con = self.pool.get().await?;
        let members: Vec<Vec<u8>> = con.smembers(ns_key).await?;
        Ok(members)
    }
    pub async fn add_to_u64_set_internal(&self, ns_key: &str, member: u64) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.sadd(ns_key, member).await?;
        Ok(())
    }
    pub async fn remove_from_u64_set_internal(&self, ns_key: &str, member: u64) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.srem(ns_key, member).await?;
        Ok(())
    }
    pub async fn get_u64_set_internal(&self, ns_key: &str) -> anyhow::Result<Vec<u64>> {
        let mut con = self.pool.get().await?;
        let members: Vec<u64> = con.smembers(ns_key).await?;
        Ok(members)
    }

    pub async fn push_to_generic_u64_queue_internal(&self, queue_key: &str, item: u64) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.rpush(queue_key, item).await?;
        Ok(())
    }
    pub async fn wait_for_generic_u64_queue_internal(&self, queue_key: &str) -> anyhow::Result<u64> {
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

    pub async fn push_to_generic_bytes_queue_internal(&self, queue_key: &str, item: &[u8]) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.rpush(queue_key, item).await?;
        Ok(())
    }
    pub async fn push_many_to_generic_bytes_queue_internal(&self, queue_key: &str, items: &[Vec<u8>]) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;

        let _: () = con.rpush(queue_key, items).await?;
        Ok(())
    }
    pub async fn pop_from_generic_bytes_queue_or_none_internal(&self, queue_key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let mut con = self.pool.get().await?;
        let item: Option<Vec<u8>> = con.lpop(queue_key, NonZeroUsize::new(1)).await?;
        if let Some(i) = item {
            Ok(Some(i))
        } else {
            Ok(None)
        }
    }
    pub async fn wait_for_generic_bytes_queue_internal(&self, queue_key: &str) -> anyhow::Result<Vec<u8>> {
        let mut con = self.pool.get().await?;
        loop {
            let item: Option<Vec<u8>> = con.lpop(queue_key, NonZeroUsize::new(1)).await?;
            if let Some(i) = item {
                return Ok(i);
            } else {
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
    pub async fn dump_ro_generic_bytes_queue_internal(&self, queue_key: &str) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut con = self.pool.get().await?;
        let items: Vec<Vec<u8>> = con.lrange(queue_key, 0, -1).await?;
        Ok(items)
    }
    pub async fn dump_generic_bytes_queue_internal(&self, queue_key: &str) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut con = self.pool.get().await?;
        let items: Vec<Vec<u8>> = con.lrange(queue_key, 0, -1).await?;
        let _: () = con.del(queue_key).await?;
        Ok(items)
    }


    pub async fn push_to_generic_obj_queue_internal<T: QPDSerializable>(&self, queue_key: &str, item: &T) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let _: () = con.rpush(queue_key, item.to_bytes()?).await?;
        Ok(())
    }
    pub async fn push_many_to_generic_obj_queue_internal<T: QPDSerializable>(&self, queue_key: &str, items: &[T]) -> anyhow::Result<()> {
        let mut con = self.pool.get().await?;
        let items: Vec<Vec<u8>> = items.iter().map(|x| x.to_bytes()).collect::<anyhow::Result<_>>()?;

        let _: () = con.rpush(queue_key, items).await?;
        Ok(())
    }
    pub async fn pop_from_generic_obj_queue_or_none_internal<T: QPDSerializable>(&self, queue_key: &str) -> anyhow::Result<Option<T>> {
        let mut con = self.pool.get().await?;
        let item: Option<Vec<u8>> = con.lpop(queue_key, NonZeroUsize::new(1)).await?;
        if let Some(i) = item {
            Ok(Some(T::from_bytes(&i)?))
        } else {
            Ok(None)
        }
    }
    pub async fn wait_for_generic_obj_queue_internal<T: QPDSerializable>(&self, queue_key: &str) -> anyhow::Result<T> {
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
    pub async fn dump_ro_generic_obj_queue_internal<T: QPDSerializable>(&self, queue_key: &str) -> anyhow::Result<Vec<T>> {
        let mut con = self.pool.get().await?;
        let items: Vec<Vec<u8>> = con.lrange(queue_key, 0, -1).await?;
        let result: Vec<T> = items.into_iter().map(|x| T::from_bytes(&x)).collect::<anyhow::Result<_>>()?;
        Ok(result)
    }
    pub async fn dump_generic_obj_queue_internal<T: QPDSerializable>(&self, queue_key: &str) -> anyhow::Result<Vec<T>> {
        let mut con = self.pool.get().await?;
        let items: Vec<Vec<u8>> = con.lrange(queue_key, 0, -1).await?;
        let result: Vec<T> = items.into_iter().map(|x| T::from_bytes(&x)).collect::<anyhow::Result<_>>()?;
        let _: () = con.del(queue_key).await?;
        Ok(result)
    }
}
#[async_trait]
impl QPBasicStoreKVReader for ProofStoreRedisAsync {
    async fn get_exact_bytes(&self, table_type: u32, key: &[u8]) -> anyhow::Result<Vec<u8>>{
        self.get_bytes_generic_internal(&self.get_kv_store_key(table_type), key).await
    }
    async fn get_exact_bytes_many(&self, table_type: u32, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>>{
        self.get_many_bytes_generic_internal(&self.get_kv_store_key(table_type), keys).await
    }
}
#[async_trait]
impl QPBasicStoreKVWriter for ProofStoreRedisAsync {

    async fn set_exact_bytes(&self, table_type: u32, key: &[u8], value: &[u8]) -> anyhow::Result<()>{
        self.set_bytes_generic_internal(&self.get_kv_store_key(table_type), key, value).await
    }

    async fn set_exact_bytes_many(&self, table_type: u32, entries: Vec<QPDPair<Vec<u8>, Vec<u8>>>) -> anyhow::Result<()>{
        self.set_many_bytes_generic_internal(&self.get_kv_store_key(table_type), entries).await
    }
    
}


#[async_trait]
impl QPTempStoreKVU64Reader for ProofStoreRedisAsync {
    async fn get_iu64_generic(&self, table_type: u32, key: &[u8]) -> anyhow::Result<u64>{
        self.get_iu64_generic_internal(&self.get_kv_store_key(table_type), key).await
    }
}

#[async_trait]
impl QPTempStoreKVU64Writer for ProofStoreRedisAsync {


    async fn set_iu64_generic(&self, table_type: u32, key: &[u8], value: u64) -> anyhow::Result<()>{
        self.set_iu64_generic_internal(&self.get_kv_store_key(table_type), key, value as i64).await
    }
    async fn inc_iu64_generic(&self, table_type: u32, key: &[u8], delta: i64) -> anyhow::Result<u64> {
        self.inc_iu64_generic_internal(&self.get_kv_store_key(table_type), key, delta).await
    }
    
}

#[async_trait]
impl QPTempQueueEmphemeralPublisher for ProofStoreRedisAsync {

    async fn push_bytes_to_ephemeral_queue(&self, queue_type: QPEphemeralQueueType, unique_id: u128, value: &[u8]) -> anyhow::Result<()>{
        self.push_to_generic_bytes_queue_internal(&self.get_ephemeral_queue_key(queue_type as u32, unique_id), value).await
    }
    
    async fn push_many_bytes_to_ephemeral_queue(&self, queue_type: QPEphemeralQueueType, unique_id: u128, values: &[Vec<u8>]) -> anyhow::Result<()>{
        self.push_many_to_generic_bytes_queue_internal(&self.get_ephemeral_queue_key(queue_type as u32, unique_id), values).await
    }
}

#[async_trait]
impl QPTempQueueEmphemeralSubscriber for ProofStoreRedisAsync {
 
    async fn dump_entire_ephemeral_queue(&self, queue_type: QPEphemeralQueueType, unique_id: u128) -> anyhow::Result<Vec<Vec<u8>>>{
        self.dump_generic_bytes_queue_internal(&self.get_ephemeral_queue_key(queue_type as u32, unique_id)).await
    }

    async fn pop_bytes_from_emphemeral_queue_or_none(&self, queue_type: QPEphemeralQueueType, unique_id: u128) -> anyhow::Result<Option<Vec<u8>>>{
        self.pop_from_generic_bytes_queue_or_none_internal(&self.get_ephemeral_queue_key(queue_type as u32, unique_id)).await
    }

    async fn wait_for_pop_bytes_from_emphemeral_queue(&self, queue_type: QPEphemeralQueueType, unique_id: u128, _timeout_ms: u64) -> anyhow::Result<Vec<u8>>{
        self.wait_for_generic_bytes_queue_internal(&self.get_ephemeral_queue_key(queue_type as u32, unique_id)).await
    }
   
}
