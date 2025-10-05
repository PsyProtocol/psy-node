
use std::{num::NonZeroUsize, time::Duration};

use async_trait::async_trait;
use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use parth_core::{data::serializable::{QPDPair, QPDSerializable}, utils::auto_implement::QAutoImplementGeneric, QJobIdSerialized};
use psy_node_core::store::traits::{proof_store::{QParthProofStoreReader, QParthProofStoreWriter}, temp_db::{QTempDatabaseCounterWriterBase, QTempDatabaseKVReaderBase, QTempDatabaseRawCounterReaderBase, QTempDatabaseRawCounterWriterBase, QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase}};
use redis::AsyncCommands as _;
use tokio::time::sleep;

pub const REDIS_TMP_PROOF_STORE_PREFIX: &str = "TMPPSV1";
pub const REDIS_TMP_KV_STORE_PREFIX: &str = "TKVSV1";
fn get_tmp_kv_store_ns_key(root_prefix: &str, realm_id: u64, realm_sub_id: u64) -> String {
    format!("{}-{}-{}-{}", REDIS_TMP_KV_STORE_PREFIX, root_prefix, realm_id, realm_sub_id)
}

fn get_tmp_proof_store_ns_key(root_prefix: &str, realm_id: u64, realm_sub_id: u64) -> String {
    format!("{}-{}-{}-{}", REDIS_TMP_PROOF_STORE_PREFIX, root_prefix, realm_id, realm_sub_id)
}

#[derive(Debug, Clone)]
pub struct StandardRedisStore {
    pub pool: Pool<RedisConnectionManager>,
    pub root_prefix: String,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub proof_store_namespace: String,
    pub kv_store_namespace: String,
}


impl StandardRedisStore {
    pub fn new(
        pool: Pool<RedisConnectionManager>,
        root_prefix: String,
        realm_id: u64,
        realm_sub_id: u64,
    ) -> Self {
        Self {
            pool,
            proof_store_namespace: get_tmp_proof_store_ns_key(&root_prefix, realm_id, realm_sub_id),
            kv_store_namespace: get_tmp_kv_store_ns_key(&root_prefix, realm_id, realm_sub_id),
            root_prefix,
            realm_id,
            realm_sub_id,
        }
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
    pub async fn get_many_bytes_generic_internal_ref(&self, ns_key: &str, keys: &[&[u8]]) -> anyhow::Result<Vec<Vec<u8>>> {
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
    pub async fn set_many_bytes_generic_internal_tuple(&self, ns_key: &str, items: &[(Vec<u8>, Vec<u8>)]) -> anyhow::Result<()> {

        let mut con = self.pool.get().await?;
        let _: () = con.hset_multiple(ns_key, &items).await?;
        Ok(())
    }
    pub async fn set_many_bytes_generic_internal_ref(&self, ns_key: &str, items: &[QPDPair<Vec<u8>, Vec<u8>>]) -> anyhow::Result<()> {

        let mut con = self.pool.get().await?;
        let _: () = con.hset_multiple(ns_key, &items.into_iter().map(|x| (&x.key, &x.value)).collect::<Vec<_>>()).await?;
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
impl QParthProofStoreReader for StandardRedisStore {

    async fn get_proof_bytes_by_job_id<J:  Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J) -> anyhow::Result<Option<Vec<u8>>> {
        let job_id_bytes = job_id.into().to_vec();
        let data = self.get_bytes_generic_internal(&self.proof_store_namespace, &job_id_bytes).await?;
        if data.is_empty() {
            Ok(None)
        } else {
            Ok(Some(data))
        }
    }
    async fn get_proof_by_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync, P: QPDSerializable>(&self, job_id: J) -> anyhow::Result<Option<P>>{
        let job_id_bytes = job_id.into().to_vec();
        let data = self.get_bytes_generic_internal(&self.proof_store_namespace, &job_id_bytes).await?;
        if data.is_empty() {
            Ok(None)
        } else {
            let proof: P = P::from_bytes(&data)?;
            Ok(Some(proof))
        }
    }
    async fn contains_proof_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J) -> anyhow::Result<bool> {
        let job_id_bytes = job_id.into().to_vec();
        let data = self.get_bytes_generic_internal(&self.proof_store_namespace, &job_id_bytes).await?;
        Ok(!data.is_empty())

    }
    
}

#[async_trait]
impl QParthProofStoreWriter for StandardRedisStore {
    async fn put_proof_bytes_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J, proof_bytes: &[u8]) -> anyhow::Result<()>{
        let job_id_bytes = job_id.into().to_vec();
        self.set_bytes_generic_internal(&self.proof_store_namespace, &job_id_bytes, proof_bytes).await
    }
    async fn put_proof_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync, P: QPDSerializable + Send + Sync>(&self, job_id: J, proof: &P) -> anyhow::Result<()>{
        let job_id_bytes = job_id.into().to_vec();
        let proof_bytes = proof.to_bytes()?;
        self.set_bytes_generic_internal(&self.proof_store_namespace, &job_id_bytes, &proof_bytes).await
    }
}

#[async_trait]
impl QTempDatabaseRawKVReaderBase for StandardRedisStore {

    async fn qtdb_raw_kv_get_value(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let data = self.get_bytes_generic_internal(&self.kv_store_namespace, key).await?;
        if data.is_empty() {
            Ok(None)
        } else {
            Ok(Some(data))
        }
    }
    async fn qtdb_raw_kv_get_many_values(&self, keys: &[&[u8]]) -> anyhow::Result<Vec<Option<Vec<u8>>>>{
        let data = self.get_many_bytes_generic_internal_ref(&self.kv_store_namespace, keys).await?;
        Ok(data.into_iter().map(|v| if v.is_empty() { None } else { Some(v) }).collect())

    }
    async fn qtdb_raw_kv_get_many_values_vec(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Option<Vec<u8>>>>{
        let data = self.get_many_bytes_generic_internal(&self.kv_store_namespace, keys).await?;
        Ok(data.into_iter().map(|v| if v.is_empty() { None } else { Some(v) }).collect())
    }
    async fn qtdb_raw_kv_contains_key(&self, key: &[u8]) -> anyhow::Result<bool> {
        let data = self.get_bytes_generic_internal(&self.kv_store_namespace, key).await?;
        Ok(!data.is_empty())
    }
}

#[async_trait]
impl QTempDatabaseRawKVWriterBase for StandardRedisStore {
    async fn qtdb_raw_kv_put_value(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()>{
        self.set_bytes_generic_internal(&self.kv_store_namespace, key, value).await
    }
    async fn qtdb_raw_kv_delete_key(&self, key: &[u8]) -> anyhow::Result<()>{
        let mut con = self.pool.get().await?;
        let _: () = con.hdel(&self.kv_store_namespace, key).await?;
        Ok(())
    }
    async fn qtdb_raw_kv_put_many_values(&self, entries: &[QPDPair<Vec<u8>, Vec<u8>>]) -> anyhow::Result<()>{
        self.set_many_bytes_generic_internal_ref(&self.kv_store_namespace, entries).await
    }
    async fn qtdb_raw_kv_put_many_values_tuple(&self, entries: &[(Vec<u8>, Vec<u8>)]) -> anyhow::Result<()>{
        self.set_many_bytes_generic_internal_tuple(&self.kv_store_namespace, entries).await
    }



}
#[async_trait]
impl QTempDatabaseRawCounterReaderBase for StandardRedisStore {
    async fn qtdb_raw_counter_get_value(&self, key: &[u8]) -> anyhow::Result<i64> {
        let value = self.get_iu64_generic_internal(&self.kv_store_namespace, key).await?;
        Ok(value as i64)
    }
}

#[async_trait]
impl QTempDatabaseRawCounterWriterBase for StandardRedisStore {

    async fn qtdb_raw_counter_increment_by(&self, key: &[u8], increment_by: i64) -> anyhow::Result<i64>{
        let new_value = self.inc_iu64_generic_internal(&self.kv_store_namespace, key, increment_by).await?;
        Ok(new_value as i64)

    }
    async fn qtdb_raw_counter_set_value(&self, key: &[u8], value: i64) -> anyhow::Result<()> {
        self.set_iu64_generic_internal(&self.kv_store_namespace, key, value).await
    }
}

impl QAutoImplementGeneric for StandardRedisStore {}

