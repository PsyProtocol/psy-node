use std::time::Duration;

use async_trait::async_trait;
use fred::{
    interfaces::*,
    prelude::*,
    types::{Builder, Map, Value},
};
use parth_core::{
    data::{
        queue::queue_key::{PCoreQueueItemBase, PCoreStandardQueueKeyForRealm, QPBaseQueueType},
        serializable::{QPDPair, QPDSerializable},
    },
    utils::auto_implement::QAutoImplementGeneric,
    QCoreProcCheckpointUniqueId, QJobIdSerialized,
};
use psy_node_core::{
    queue::{
        ephemeral::{QStandardEphemeralQueuePublisher, QStandardEphemeralQueueSubscriber},
        infrastructure::QStandardQueueBase,
    },
    store::traits::{
        proof_store::{QParthProofStoreReader, QParthProofStoreWriter},
        temp_db::{
            QTempDatabaseRawCounterReaderBase, QTempDatabaseRawCounterWriterBase,
            QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase,
        },
    },
};

// Fred Pool alias
type RedisPool = Pool;

pub const REDIS_TMP_PROOF_STORE_PREFIX: &str = "TMPPSV1";
pub const REDIS_TMP_KV_STORE_PREFIX: &str = "TKVSV1";

fn get_tmp_kv_store_ns_key(root_prefix: &str, realm_id: u64, realm_sub_id: u64) -> String {
    format!("{}-{}-{}-{}", REDIS_TMP_KV_STORE_PREFIX, root_prefix, realm_id, realm_sub_id)
}

fn get_tmp_proof_store_ns_key(root_prefix: &str, realm_id: u64, realm_sub_id: u64) -> String {
    format!("{}-{}-{}-{}", REDIS_TMP_PROOF_STORE_PREFIX, root_prefix, realm_id, realm_sub_id)
}

fn get_tmp_proof_store_bucket_ns_key(
    root_prefix: &str,
    realm_id: u64,
    realm_sub_id: u64,
    unique_pending_id: u64,
) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        REDIS_TMP_PROOF_STORE_PREFIX, root_prefix, realm_id, realm_sub_id, unique_pending_id
    )
}

/// Create a high-performance fred RedisPool
pub async fn new_redis_async_pool(
    redis_url: &str,
    pool_size: usize,
) -> anyhow::Result<RedisPool> {
    let config = Config::from_url(redis_url)?;

    let policy = ReconnectPolicy::new_exponential(
        0,
        100, // ms
        10_000, // ms (10s)
        10,
    );

    // FIX 1: Use the Builder to set connection config and policy separately
    let pool = Builder::from_config(config)
        .with_connection_config(|cc| {
            // TCP settings go here in v10
            cc.tcp = TcpConfig {
                nodelay: Some(true),
                ..Default::default()
            };
            cc.connection_timeout = Duration::from_secs(5);
        })
        // Policy is set on the builder, not the config struct
        .set_policy(policy) 
        .build_pool(pool_size)?;

    // FIX 2: v10 uses init() to connect and wait
    pool.init().await?;

    tracing::info!("✅ Created fred RedisPool with size {}", pool_size);

    Ok(pool)
}

#[derive(Debug, Clone)]
pub struct StandardFredRedisStore {
    pub client: RedisPool,
    pub root_prefix: String,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub proof_store_namespace: String,
    pub kv_store_namespace: String,
}

impl StandardFredRedisStore {
    pub fn new(
        client: RedisPool,
        root_prefix: String,
        realm_id: u64,
        realm_sub_id: u64,
    ) -> Self {
        Self {
            proof_store_namespace: get_tmp_proof_store_ns_key(&root_prefix, realm_id, realm_sub_id),
            kv_store_namespace: get_tmp_kv_store_ns_key(&root_prefix, realm_id, realm_sub_id),
            client,
            root_prefix,
            realm_id,
            realm_sub_id,
        }
    }

    pub async fn get_bytes_generic_internal(&self, ns_key: &str, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        // HGET returns Option<Value>. Convert None -> empty vec.
        let val: Option<Vec<u8>> = self.client.hget(ns_key, key).await?;
        Ok(val.unwrap_or_default())
    }

    pub async fn get_many_bytes_generic_internal(&self, ns_key: &str, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>> {
        // Fred requires `hmget` for multiple fields, and keys need to be converted to `MultipleKeys` (Vec<Key>)
        let keys_converted: Vec<Key> = keys.iter().map(|k| Key::from(&k[..])).collect();
        let result: Vec<Option<Vec<u8>>> = self.client.hmget(ns_key, keys_converted).await?;
        Ok(result.into_iter().map(|opt| opt.unwrap_or_default()).collect())
    }

    pub async fn get_many_bytes_generic_internal_ref(&self, ns_key: &str, keys: &[&[u8]]) -> anyhow::Result<Vec<Vec<u8>>> {
        let keys_converted: Vec<Key> = keys.iter().map(|k| Key::from(*k)).collect();
        let result: Vec<Option<Vec<u8>>> = self.client.hmget(ns_key, keys_converted).await?;
        Ok(result.into_iter().map(|opt| opt.unwrap_or_default()).collect())
    }

    pub async fn set_bytes_generic_internal(&self, ns_key: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        let _: () = self.client.hset(ns_key, (key, value)).await?;
        Ok(())
    }

    pub async fn set_many_bytes_generic_internal(&self, ns_key: &str, items: Vec<QPDPair<Vec<u8>, Vec<u8>>>) -> anyhow::Result<()> {
        // Convert to Map for HSET
        let map: Map = items.into_iter().map(|x| (Key::from(&x.key[..]), Value::from(&x.value[..]))).collect();
        let _: () = self.client.hset(ns_key, map).await?;
        Ok(())
    }

    pub async fn set_many_bytes_generic_internal_tuple(&self, ns_key: &str, items: &[(Vec<u8>, Vec<u8>)]) -> anyhow::Result<()> {
        let map: Map = items.iter().map(|(k, v)| (Key::from(&k[..]), Value::from(&v[..]))).collect();
        let _: () = self.client.hset(ns_key, map).await?;
        Ok(())
    }

    pub async fn set_many_bytes_generic_internal_ref(&self, ns_key: &str, items: &[QPDPair<Vec<u8>, Vec<u8>>]) -> anyhow::Result<()> {
        let map: Map = items.iter().map(|x| (Key::from(&x.key[..]), Value::from(&x.value[..]))).collect();
        let _: () = self.client.hset(ns_key, map).await?;
        Ok(())
    }

    pub async fn get_iu64_generic_internal(&self, ns_key: &str, key: &[u8]) -> anyhow::Result<u64> {
        let value: Option<i64> = self.client.hget(ns_key, key).await?;
        Ok(value.unwrap_or(0).max(0) as u64)
    }

    pub async fn set_iu64_generic_internal(&self, ns_key: &str, key: &[u8], value: i64) -> anyhow::Result<()> {
        let _: () = self.client.hset(ns_key, (key, value)).await?;
        Ok(())
    }

    pub async fn inc_iu64_generic_internal(&self, ns_key: &str, key: &[u8], amount: i64) -> anyhow::Result<u64> {
        // HINCRBY returns the new value
        let val: i64 = self.client.hincrby(ns_key, key, amount).await?;
        Ok(val.max(0) as u64)
    }

    pub async fn add_to_set_generic_internal(&self, ns_key: &str, member: &[u8]) -> anyhow::Result<()> {
        let _: () = self.client.sadd(ns_key, member).await?;
        Ok(())
    }

    pub async fn remove_from_set_generic_internal(&self, ns_key: &str, member: &[u8]) -> anyhow::Result<()> {
        let _: () = self.client.srem(ns_key, member).await?;
        Ok(())
    }

    pub async fn get_set_generic_internal(&self, ns_key: &str) -> anyhow::Result<Vec<Vec<u8>>> {
        Ok(self.client.smembers(ns_key).await?)
    }

    pub async fn add_to_u64_set_internal(&self, ns_key: &str, member: u64) -> anyhow::Result<()> {
        let _: () = self.client.sadd(ns_key, member).await?;
        Ok(())
    }

    pub async fn remove_from_u64_set_internal(&self, ns_key: &str, member: u64) -> anyhow::Result<()> {
        let _: () = self.client.srem(ns_key, member).await?;
        Ok(())
    }

    pub async fn get_u64_set_internal(&self, ns_key: &str) -> anyhow::Result<Vec<u64>> {
        Ok(self.client.smembers(ns_key).await?)
    }

    pub async fn push_to_generic_u64_queue_internal(&self, queue_key: &str, item: u64) -> anyhow::Result<()> {
        let _: () = self.client.rpush(queue_key, item).await?;
        Ok(())
    }

    pub async fn wait_for_generic_u64_queue_internal(&self, queue_key: &str) -> anyhow::Result<u64> {
        // Optimization: Use BLPOP (0.0 means infinite block) instead of polling loop
        // blpop returns (key, value)
        let (_key, val): (String, u64) = self.client.blpop(queue_key, 0.0).await?;
        Ok(val)
    }

    pub async fn push_to_generic_bytes_queue_internal(&self, queue_key: &str, item: &[u8]) -> anyhow::Result<()> {
        let _: () = self.client.rpush(queue_key, item).await?;
        Ok(())
    }

    pub async fn push_many_to_generic_bytes_queue_internal(&self, queue_key: &str, items: &[Vec<u8>]) -> anyhow::Result<()> {
        // Convert &[Vec<u8>] to Vec<Value>
        let values: Vec<Value> = items.iter().map(|x| Value::from(&x[..])).collect();
        let _: () = self.client.rpush(queue_key, values).await?;
        Ok(())
    }

    pub async fn pop_from_generic_bytes_queue_or_none_internal(&self, queue_key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        // lpop with count returns Vec.
        let items: Vec<Vec<u8>> = self.client.lpop(queue_key, Some(1)).await?;
        Ok(items.into_iter().next())
    }

    pub async fn wait_for_generic_bytes_queue_internal(&self, queue_key: &str) -> anyhow::Result<Vec<u8>> {
        // Optimization: BLPOP
        let (_key, val): (String, Vec<u8>) = self.client.blpop(queue_key, 0.0).await?;
        Ok(val)
    }

    pub async fn dump_ro_generic_bytes_queue_internal(&self, queue_key: &str) -> anyhow::Result<Vec<Vec<u8>>> {
        // 0 and -1 must be i64
        Ok(self.client.lrange(queue_key, 0, -1).await?)
    }

    pub async fn dump_generic_bytes_queue_internal(&self, queue_key: &str) -> anyhow::Result<Vec<Vec<u8>>> {
        let items = self.dump_ro_generic_bytes_queue_internal(queue_key).await?;
        // Fred 10 uses `del` which takes a Key or MultipleKeys.
        let _: () = self.client.del(queue_key).await?;
        Ok(items)
    }

    pub async fn push_to_generic_obj_queue_internal<T: QPDSerializable>(&self, queue_key: &str, item: &T) -> anyhow::Result<()> {
        let _: () = self.client.rpush(queue_key, item.to_bytes()?).await?;
        Ok(())
    }

    pub async fn push_many_to_generic_obj_queue_internal<T: QPDSerializable>(&self, queue_key: &str, items: &[T]) -> anyhow::Result<()> {
        let items_bytes: Vec<Value> = items
            .iter()
            .map(|x| x.to_bytes().map(|x| Value::from(&x[..])))
            .collect::<anyhow::Result<_>>()?;
        let _: () = self.client.rpush(queue_key, items_bytes).await?;
        Ok(())
    }

    pub async fn pop_from_generic_obj_queue_or_none_internal<T: QPDSerializable>(&self, queue_key: &str) -> anyhow::Result<Option<T>> {
        if let Some(bytes) = self.pop_from_generic_bytes_queue_or_none_internal(queue_key).await? {
            Ok(Some(T::from_bytes(&bytes)?))
        } else {
            Ok(None)
        }
    }

    pub async fn wait_for_generic_obj_queue_internal<T: QPDSerializable>(&self, queue_key: &str) -> anyhow::Result<T> {
        let bytes = self.wait_for_generic_bytes_queue_internal(queue_key).await?;
        Ok(T::from_bytes(&bytes)?)
    }

    pub async fn dump_ro_generic_obj_queue_internal<T: QPDSerializable>(&self, queue_key: &str) -> anyhow::Result<Vec<T>> {
        let items_bytes = self.dump_ro_generic_bytes_queue_internal(queue_key).await?;
        items_bytes.into_iter().map(|x| T::from_bytes(&x)).collect::<anyhow::Result<_>>()
    }

    pub async fn dump_generic_obj_queue_internal<T: QPDSerializable>(&self, queue_key: &str) -> anyhow::Result<Vec<T>> {
        let items_bytes = self.dump_generic_bytes_queue_internal(queue_key).await?;
        items_bytes.into_iter().map(|x| T::from_bytes(&x)).collect::<anyhow::Result<_>>()
    }
}

#[async_trait]
impl QStandardQueueBase for StandardFredRedisStore {
    async fn ensure_stream(&self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn ensure_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait]
impl QStandardEphemeralQueuePublisher for StandardFredRedisStore {
    async fn publish_ephemeral_queue_item_bytes_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item_bytes: &[u8],
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        let _: () = self.client.rpush(&subject, item_bytes).await?;
        Ok(())
    }

    async fn publish_many_ephemeral_queue_items_bytes_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items_bytes: &[&[u8]],
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        // Explicit cast from slice of slices to Vec<Value>
        let args: Vec<Value> = items_bytes.iter().map(|x| Value::from(*x)).collect();
        let _: () = self.client.rpush(&subject, args).await?;
        Ok(())
    }

    async fn publish_ephemeral_queue_item_owned_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        let _: () = self.client.rpush(&subject, item_bytes).await?;
        Ok(())
    }

    async fn publish_many_ephemeral_queue_items_owned_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items_bytes: Vec<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        // Explicit cast
        let args: Vec<Value> = items_bytes.into_iter().map(|x| Value::from(&x[..])).collect();
        let _: () = self.client.rpush(&subject, args).await?;
        Ok(())
    }

    async fn publish_ephemeral_queue_item_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item: &QK::QueueItem,
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        let _: () = self.client.rpush(&subject, item.encode_queue_item_vec()?).await?;
        Ok(())
    }

    async fn publish_many_ephemeral_queue_items_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: &[&QK::QueueItem],
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        let items_bytes: Vec<Vec<u8>> = items
            .iter()
            .map(|x| x.encode_queue_item_vec())
            .collect::<anyhow::Result<Vec<_>>>()?;
        let items_bytes: Vec<Value> = items_bytes.iter().map(|x| Value::from(&x[..])).collect();

        let _: () = self.client.rpush(&subject, items_bytes).await?;
        Ok(())
    }

    async fn publish_ephemeral_queue_item_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item: QK::QueueItem,
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        let _: () = self.client.rpush(&subject, item.encode_queue_item_vec()?).await?;
        Ok(())
    }

    async fn publish_many_ephemeral_queue_items_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: Vec<QK::QueueItem>,
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        let items_bytes: Vec<Value> = items
            .into_iter()
            .map(|x| x.encode_queue_item_vec().map(|x| Value::from(&x[..])))
            .collect::<anyhow::Result<_>>()?;
        let _: () = self.client.rpush(&subject, items_bytes).await?;
        Ok(())
    }

    async fn publish_many_ephemeral_queue_items<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: &[QK::QueueItem],
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        let items_bytes: Vec<Value> = items
            .iter()
            .map(|x| x.encode_queue_item_vec().map(|x| Value::from(&x[..])))
            .collect::<anyhow::Result<_>>()?;
        let _: () = self.client.rpush(&subject, items_bytes).await?;
        Ok(())
    }

}

#[async_trait]
impl QStandardEphemeralQueueSubscriber for StandardFredRedisStore {
    async fn wait_for_ephemeral_queue_item_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        timeout_ms: u64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        let timeout_secs = timeout_ms as f64 / 1000.0;
        
        // Use BLPOP
        match self.client.blpop::<Option<(String, Vec<u8>)>, _>(&subject, timeout_secs).await? {
            Some((_k, v)) => Ok(Some(v)),
            None => Ok(None) // Timeout hit
        }
    }

    async fn wait_for_ephemeral_queue_item<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        timeout_ms: u64,
    ) -> anyhow::Result<Option<QK::QueueItem>> {
        let val_opt = self.wait_for_ephemeral_queue_item_bytes(queue_key, realm_id, realm_sub_id, unique_id, task_group, timeout_ms).await?;
        
        if let Some(v) = val_opt {
             Ok(Some(QK::QueueItem::decode_queue_item_ref(&v)?))
        } else {
            Ok(None)
        }
    }

    async fn dump_entire_ephemeral_queue_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        max_items: usize,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        // lrange requires i64
        let items: Vec<Vec<u8>> = self.client.lrange(&subject, 0, (max_items as i64) - 1).await?;
        if !items.is_empty() {
            // ltrim requires i64
            let _: () = self.client.ltrim(&subject, items.len() as i64, -1).await?;
        }
        Ok(items)
    }

    async fn dump_entire_ephemeral_queue<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        max_items: usize,
    ) -> anyhow::Result<Vec<QK::QueueItem>> {
        let items_bytes = self.dump_entire_ephemeral_queue_bytes(queue_key, realm_id, realm_sub_id, unique_id, task_group, max_items).await?;
        let result: Vec<QK::QueueItem> = items_bytes
            .into_iter()
            .map(|x| QK::QueueItem::decode_queue_item_ref(&x))
            .collect::<anyhow::Result<_>>()?;
        Ok(result)
    }

    async fn consume_ephemeral_queue_item_or_none_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        let items: Vec<Vec<u8>> = self.client.lpop(&subject, Some(1)).await?;
        Ok(items.into_iter().next())
    }

    async fn consume_ephemeral_queue_item_or_none<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
    ) -> anyhow::Result<Option<QK::QueueItem>> {
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        let items: Vec<Vec<u8>> = self.client.lpop(&subject, Some(1)).await?;
        if let Some(i) = items.into_iter().next() {
            Ok(Some(QK::QueueItem::decode_queue_item_ref(&i)?))
        } else {
            Ok(None)
        }
    }

}

#[async_trait]
impl QParthProofStoreReader for StandardFredRedisStore {
    async fn get_proof_bytes_by_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J, unique_pending_id: u64) -> anyhow::Result<Option<Vec<u8>>> {
        let job_id_bytes = job_id.into().to_vec();
        let bucket = get_tmp_proof_store_bucket_ns_key(&self.root_prefix, self.realm_id, self.realm_sub_id, unique_pending_id);
        // hget returns Option<Value> or Value::Null -> maps to Option<Vec<u8>> with correct type hint
        let data: Option<Vec<u8>> = self.client.hget(&bucket, &job_id_bytes[..]).await?;
        Ok(data.filter(|d| !d.is_empty()))
    }

    async fn get_proof_by_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync, P: QPDSerializable>(&self, job_id: J, unique_pending_id: u64) -> anyhow::Result<Option<P>> {
        let job_id_bytes = job_id.into().to_vec();
        let bucket = get_tmp_proof_store_bucket_ns_key(&self.root_prefix, self.realm_id, self.realm_sub_id, unique_pending_id);
        let data: Option<Vec<u8>> = self.client.hget(&bucket, &job_id_bytes[..]).await?;
        if let Some(d) = data {
             if d.is_empty() { Ok(None) } else { Ok(Some(P::from_bytes(&d)?)) }
        } else {
            Ok(None)
        }
    }

    async fn contains_proof_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J, unique_pending_id: u64) -> anyhow::Result<bool> {
        let job_id_bytes = job_id.into().to_vec();
        let bucket = get_tmp_proof_store_bucket_ns_key(&self.root_prefix, self.realm_id, self.realm_sub_id, unique_pending_id);
        let data: bool = self.client.hexists(&bucket, &job_id_bytes[..]).await?;
        Ok(data)
    }
}

#[async_trait]
impl QParthProofStoreWriter for StandardFredRedisStore {
    async fn put_proof_bytes_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J, unique_pending_id: u64, proof_bytes: &[u8]) -> anyhow::Result<()> {
        let job_id_bytes = job_id.into().to_vec();
        let bucket = get_tmp_proof_store_bucket_ns_key(&self.root_prefix, self.realm_id, self.realm_sub_id, unique_pending_id);
        // A pending checkpoint may legitimately wait longer than a fixed TTL
        // for a downstream proof. The processor deletes the entire pending-id
        // bucket after checkpoint commit, so expiry here is both unnecessary
        // and unsafe for the proving pipeline.
        self.set_bytes_generic_internal(&bucket, &job_id_bytes, proof_bytes)
            .await
    }
    async fn put_proof_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync, P: QPDSerializable + Send + Sync>(
        &self,
        job_id: J,
        unique_pending_id: u64,
        proof: &P,
    ) -> anyhow::Result<()> {
        let job_id_bytes = job_id.into().to_vec();
        let bucket = get_tmp_proof_store_bucket_ns_key(&self.root_prefix, self.realm_id, self.realm_sub_id, unique_pending_id);
        let proof_bytes = proof.to_bytes()?;
        self.set_bytes_generic_internal(&bucket, &job_id_bytes, &proof_bytes)
            .await
    }
    async fn delete_all_proofs_for_pending_id(&self, unique_pending_id: u64) -> anyhow::Result<()> {
        let bucket = get_tmp_proof_store_bucket_ns_key(&self.root_prefix, self.realm_id, self.realm_sub_id, unique_pending_id);
        let _: i64 = self.client.del(&bucket).await?;
        Ok(())
    }
}

#[async_trait]
impl QTempDatabaseRawKVReaderBase for StandardFredRedisStore {
    async fn qtdb_raw_kv_get_value(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let data: Option<Vec<u8>> = self.client.hget(&self.kv_store_namespace, key).await?;
        Ok(data.filter(|x| !x.is_empty()))
    }

    async fn qtdb_raw_kv_get_many_values_vec_owned(&self, keys: Vec<Vec<u8>>) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let keys_conv: Vec<Key> = keys.into_iter().map(|k| Key::from(&k[..])).collect();
        let data: Vec<Option<Vec<u8>>> = self.client.hmget(&self.kv_store_namespace, keys_conv).await?;
        Ok(data.into_iter().map(|v| v.filter(|x| !x.is_empty())).collect())
    }

    async fn qtdb_raw_kv_get_many_values(&self, keys: &[&[u8]]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let keys_conv: Vec<Key> = keys.iter().map(|k| Key::from(*k)).collect();
        let data: Vec<Option<Vec<u8>>> = self.client.hmget(&self.kv_store_namespace, keys_conv).await?;
        Ok(data.into_iter().map(|v| v.filter(|x| !x.is_empty())).collect())
    }

    async fn qtdb_raw_kv_get_many_values_vec(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let keys_conv: Vec<Key> = keys.iter().map(|k| Key::from(&k[..])).collect();
        let data: Vec<Option<Vec<u8>>> = self.client.hmget(&self.kv_store_namespace, keys_conv).await?;
        Ok(data.into_iter().map(|v| v.filter(|x| !x.is_empty())).collect())
    }

    async fn qtdb_raw_kv_contains_key(&self, key: &[u8]) -> anyhow::Result<bool> {
        let exists: bool = self.client.hexists(&self.kv_store_namespace, key).await?;
        Ok(exists)
    }
}

#[async_trait]
impl QTempDatabaseRawKVWriterBase for StandardFredRedisStore {
    async fn qtdb_raw_kv_put_value(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        self.set_bytes_generic_internal(&self.kv_store_namespace, key, value).await
    }

    async fn qtdb_raw_kv_delete_key(&self, key: &[u8]) -> anyhow::Result<()> {
        let _: () = self.client.hdel(&self.kv_store_namespace, key).await?;
        Ok(())
    }

    async fn qtdb_raw_kv_put_many_values(&self, entries: &[QPDPair<Vec<u8>, Vec<u8>>]) -> anyhow::Result<()> {
        self.set_many_bytes_generic_internal_ref(&self.kv_store_namespace, entries).await
    }

    async fn qtdb_raw_kv_put_many_values_tuple(&self, entries: &[(Vec<u8>, Vec<u8>)]) -> anyhow::Result<()> {
        self.set_many_bytes_generic_internal_tuple(&self.kv_store_namespace, entries).await
    }

    async fn qtdb_raw_kv_put_many_values_tuple_ref<'a>(&self, entries: &[(&'a [u8], &'a [u8])]) -> anyhow::Result<()> {
        let map: Map = entries.iter().map(|(k, v)| (Key::from(*k), Value::from(*v))).collect();
        let _: () = self.client.hset(&self.kv_store_namespace, map).await?;
        Ok(())
    }

    async fn qtdb_raw_kv_put_many_values_tuple_owned(&self, entries: Vec<(Vec<u8>, Vec<u8>)>) -> anyhow::Result<()> {
        self.set_many_bytes_generic_internal_tuple(&self.kv_store_namespace, &entries).await
    }

    async fn qtdb_raw_kv_put_many_values_buffer<const KEY_SIZE: usize, const VALUE_SIZE: usize>(&self, data: &[u8]) -> anyhow::Result<()> {
        let combined_size: usize = KEY_SIZE + VALUE_SIZE;
        if data.len() % combined_size != 0 {
            return Err(anyhow::anyhow!("Data length is not a multiple of combined key and value size"));
        }
        if data.len() == 0 {
            return Ok(());
        }
        let entry_count = data.len() / combined_size;
        
        let mut map = Map::new();
        map.reserve(entry_count);
        for i in 0..entry_count {
            let start = i * combined_size;
            let key = &data[start..start + KEY_SIZE];
            let value = &data[start + KEY_SIZE..start + combined_size];
            map.insert(Key::from(key), Value::from(value));
        }
        
        let _: () = self.client.hset(&self.kv_store_namespace, map).await?;
        Ok(())
    }
}

#[async_trait]
impl QTempDatabaseRawCounterReaderBase for StandardFredRedisStore {
    async fn qtdb_raw_counter_get_value(&self, key: &[u8]) -> anyhow::Result<i64> {
        let value = self.get_iu64_generic_internal(&self.kv_store_namespace, key).await?;
        Ok(value as i64)
    }
}

#[async_trait]
impl QTempDatabaseRawCounterWriterBase for StandardFredRedisStore {
    async fn qtdb_raw_counter_increment_by(&self, key: &[u8], increment_by: i64) -> anyhow::Result<i64> {
        let new_value = self.inc_iu64_generic_internal(&self.kv_store_namespace, key, increment_by).await?;
        Ok(new_value as i64)
    }
    async fn qtdb_raw_counter_set_value(&self, key: &[u8], value: i64) -> anyhow::Result<()> {
        self.set_iu64_generic_internal(&self.kv_store_namespace, key, value).await
    }
}

impl QAutoImplementGeneric for StandardFredRedisStore {}
