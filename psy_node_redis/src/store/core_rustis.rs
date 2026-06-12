use std::{num::NonZeroUsize, time::Duration};

use async_trait::async_trait;
use rustis::{
    Result as RustisResult, client::Client, commands::{HashCommands, ListCommands, ServerCommands, SetCommands}, resp::BulkString
};
use parth_core::{
    data::{
        queue::queue_key::{PCoreQueueItemBase, PCoreStandardQueueKeyForRealm},
        serializable::{QPDPair, QPDSerializable},
    },
    utils::auto_implement::QAutoImplementGeneric,
    QCoreProcCheckpointUniqueId, QJobIdSerialized,
};
use psy_node_core::{
    queue::ephemeral::{QStandardEphemeralQueuePublisher, QStandardEphemeralQueueSubscriber},
    store::traits::{
        proof_store::{QParthProofStoreReader, QParthProofStoreWriter},
        temp_db::{
            QTempDatabaseRawCounterReaderBase, QTempDatabaseRawCounterWriterBase,
            QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase,
        },
    },
};
use tokio::time::sleep;

pub const REDIS_TMP_PROOF_STORE_PREFIX: &str = "TMPPSV1";
pub const REDIS_TMP_KV_STORE_PREFIX: &str = "TKVSV1";
fn get_tmp_kv_store_ns_key(root_prefix: &str, realm_id: u64, realm_sub_id: u64) -> String {
    format!("{}-{}-{}-{}", REDIS_TMP_KV_STORE_PREFIX, root_prefix, realm_id, realm_sub_id)
}

fn get_tmp_proof_store_ns_key(root_prefix: &str, realm_id: u64, realm_sub_id: u64) -> String {
    format!("{}-{}-{}-{}", REDIS_TMP_PROOF_STORE_PREFIX, root_prefix, realm_id, realm_sub_id)
}
fn get_tmp_proof_store_bucket_ns_key(root_prefix: &str, realm_id: u64, realm_sub_id: u64, unique_pending_id: u64) -> String {
    format!("{}-{}-{}-{}-{}", REDIS_TMP_PROOF_STORE_PREFIX, root_prefix, realm_id, realm_sub_id, unique_pending_id)
}

/// Create a new rustis Client
///
/// # Arguments
///
/// * `redis_url` - Redis URL to connect to
pub async fn new_redis_async_client(redis_url: &str) -> anyhow::Result<Client> {
    // Connect to Redis
    let client = Client::connect(redis_url).await?;

    // Optionally set client name
    if let Ok(role) = std::env::var("QED_ROLE") {
        let _ = client.client_setname(format!("rustis-{}-client", role)).await;
    }

    tracing::info!("✅ Created rustis Client");

    Ok(client)
}

#[derive(Debug, Clone)]
pub struct StandardRedisStore {
    pub client: Client,
    pub root_prefix: String,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub proof_store_namespace: String,
    pub kv_store_namespace: String,
}

impl StandardRedisStore {
    pub fn new(client: Client, root_prefix: String, realm_id: u64, realm_sub_id: u64) -> Self {
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
        let data: BulkString = self.client.hget(ns_key, key).await?;
        Ok(data.into())
    }
    pub async fn get_many_bytes_generic_internal(&self, ns_key: &str, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>> {
        let data: Vec<BulkString> = self.client.hmget(ns_key, keys).await?;
        Ok(data.into_iter().map(|d| d.into()).collect())
    }
    pub async fn get_many_bytes_generic_internal_ref(&self, ns_key: &str, keys: &[&[u8]]) -> anyhow::Result<Vec<Vec<u8>>> {
        let data: Vec<BulkString> = self.client.hmget(ns_key, keys).await?;
        Ok(data.into_iter().map(|d| d.into()).collect())
    }

    pub async fn set_bytes_generic_internal(&self, ns_key: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        let _: usize = self.client.hset(ns_key, (key, value)).await?;
        Ok(())
    }
    pub async fn set_many_bytes_generic_internal(&self, ns_key: &str, items: Vec<QPDPair<Vec<u8>, Vec<u8>>>) -> anyhow::Result<()> {
        let items: Vec<(Vec<u8>, Vec<u8>)> = items.into_iter().map(|x| (x.key, x.value)).collect();
        let _: usize = self.client.hset(ns_key, items).await?;
        Ok(())
    }
    pub async fn set_many_bytes_generic_internal_tuple(&self, ns_key: &str, items: &[(Vec<u8>, Vec<u8>)]) -> anyhow::Result<()> {
        let _: usize = self.client.hset(ns_key, items).await?;
        Ok(())
    }
    pub async fn set_many_bytes_generic_internal_ref(&self, ns_key: &str, items: &[QPDPair<Vec<u8>, Vec<u8>>]) -> anyhow::Result<()> {
        let items: Vec<(&[u8], &[u8])> = items.iter().map(|x| (&*x.key, &*x.value)).collect();
        let _: usize = self.client.hset(ns_key, items).await?;
        Ok(())
    } 

    pub async fn get_iu64_generic_internal(&self, ns_key: &str, key: &[u8]) -> anyhow::Result<u64> {
        let value: Option<i64> = self.client.hget(ns_key, key).await?;
        Ok(value.unwrap_or(0).max(0) as u64)
    }
    pub async fn set_iu64_generic_internal(&self, ns_key: &str, key: &[u8], value: i64) -> anyhow::Result<()> {
        let _: usize = self.client.hset(ns_key, (key, value)).await?;
        Ok(())
    }

    pub async fn inc_iu64_generic_internal(&self, ns_key: &str, key: &[u8], amount: i64) -> anyhow::Result<u64> {
        let new_value: i64 = self.client.hincrby(ns_key, key, amount).await?;
        Ok(new_value as u64)
    }

    pub async fn add_to_set_generic_internal(&self, ns_key: &str, member: &[u8]) -> anyhow::Result<()> {
        let _: usize = self.client.sadd(ns_key, member).await?;
        Ok(())
    }
    pub async fn remove_from_set_generic_internal(&self, ns_key: &str, member: &[u8]) -> anyhow::Result<()> {
        let _: usize = self.client.srem(ns_key, member).await?;
        Ok(())
    }
    pub async fn get_set_generic_internal(&self, ns_key: &str) -> anyhow::Result<Vec<Vec<u8>>> {
        let members: Vec<BulkString> = self.client.smembers(ns_key).await?;
        Ok(members.into_iter().map(|m| m.into()).collect())
    }
    pub async fn add_to_u64_set_internal(&self, ns_key: &str, member: u64) -> anyhow::Result<()> {
        let _: usize = self.client.sadd(ns_key, member).await?;
        Ok(())
    }
    pub async fn remove_from_u64_set_internal(&self, ns_key: &str, member: u64) -> anyhow::Result<()> {
        let _: usize = self.client.srem(ns_key, member).await?;
        Ok(())
    }
    pub async fn get_u64_set_internal(&self, ns_key: &str) -> anyhow::Result<Vec<u64>> {
        let members: Vec<u64> = self.client.smembers(ns_key).await?;
        Ok(members)
    }

    pub async fn push_to_generic_u64_queue_internal(&self, queue_key: &str, item: u64) -> anyhow::Result<()> {
        let _: usize = self.client.rpush(queue_key, item).await?;
        Ok(())
    }
    pub async fn wait_for_generic_u64_queue_internal(&self, queue_key: &str) -> anyhow::Result<u64> {
        loop {
            let item: Option<u64> = self.client.lpop(queue_key, None).await?;
            if let Some(i) = item {
                return Ok(i);
            } else {
                sleep(Duration::from_millis(100)).await;
            }
        }
    }

    pub async fn push_to_generic_bytes_queue_internal(&self, queue_key: &str, item: &[u8]) -> anyhow::Result<()> {
        let _: usize = self.client.rpush(queue_key, item).await?;
        Ok(())
    }
    pub async fn push_many_to_generic_bytes_queue_internal(&self, queue_key: &str, items: &[Vec<u8>]) -> anyhow::Result<()> {
        let _: usize = self.client.rpush(queue_key, items).await?;
        Ok(())
    }
    pub async fn pop_from_generic_bytes_queue_or_none_internal(&self, queue_key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let item: Option<Vec<u8>> = self.client.lpop(queue_key, None).await?;
        Ok(item)
    }
    pub async fn wait_for_generic_bytes_queue_internal(&self, queue_key: &str) -> anyhow::Result<Vec<u8>> {
        loop {
            let item: Option<Vec<u8>> = self.client.lpop(queue_key, None).await?;
            if let Some(i) = item {
                return Ok(i);
            } else {
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
    pub async fn dump_ro_generic_bytes_queue_internal(&self, queue_key: &str) -> anyhow::Result<Vec<Vec<u8>>> {
        let items: Vec<Vec<u8>> = self.client.lrange(queue_key, 0, -1).await?;
        Ok(items)
    }
    pub async fn dump_generic_bytes_queue_internal(&self, queue_key: &str) -> anyhow::Result<Vec<Vec<u8>>> {
        let items: Vec<Vec<u8>> = self.client.lrange(queue_key, 0, -1).await?;
        let _: () = self.client.del(queue_key).await?;
        Ok(items)
    }

    pub async fn push_to_generic_obj_queue_internal<T: QPDSerializable>(&self, queue_key: &str, item: &T) -> anyhow::Result<()> {
        let _: usize = self.client.rpush(queue_key, item.to_bytes()?).await?;
        Ok(())
    }
    pub async fn push_many_to_generic_obj_queue_internal<T: QPDSerializable>(&self, queue_key: &str, items: &[T]) -> anyhow::Result<()> {
        let items: Vec<Vec<u8>> = items.iter().map(|x| x.to_bytes()).collect::<anyhow::Result<_>>()?;
        let _: usize = self.client.rpush(queue_key, items).await?;
        Ok(())
    }
    pub async fn pop_from_generic_obj_queue_or_none_internal<T: QPDSerializable>(&self, queue_key: &str) -> anyhow::Result<Option<T>> {
        let item: Option<Vec<u8>> = self.client.lpop(queue_key, None).await?;
        if let Some(i) = item {
            Ok(Some(T::from_bytes(&i)?))
        } else {
            Ok(None)
        }
    }
    pub async fn wait_for_generic_obj_queue_internal<T: QPDSerializable>(&self, queue_key: &str) -> anyhow::Result<T> {
        loop {
            let item: Option<Vec<u8>> = self.client.lpop(queue_key, None).await?;
            if let Some(i) = item {
                return Ok(T::from_bytes(&i)?);
            } else {
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
    pub async fn dump_ro_generic_obj_queue_internal<T: QPDSerializable>(&self, queue_key: &str) -> anyhow::Result<Vec<T>> {
        let items: Vec<Vec<u8>> = self.client.lrange(queue_key, 0, -1).await?;
        let result: Vec<T> = items.into_iter().map(|x| T::from_bytes(&x)).collect::<anyhow::Result<_>>()?;
        Ok(result)
    }
    pub async fn dump_generic_obj_queue_internal<T: QPDSerializable>(&self, queue_key: &str) -> anyhow::Result<Vec<T>> {
        let items: Vec<Vec<u8>> = self.client.lrange(queue_key, 0, -1).await?;
        let result: Vec<T> = items.into_iter().map(|x| T::from_bytes(&x)).collect::<anyhow::Result<_>>()?;
        let _: () = self.client.del(queue_key).await?;
        Ok(result)
    }
}

#[async_trait]
impl QStandardEphemeralQueuePublisher for StandardRedisStore {
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

        let _: usize = self.client.rpush(&subject, item_bytes).await?;
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
        let _: usize = self.client.rpush(&subject, items_bytes).await?;
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
        let _: usize = self.client.rpush(&subject, item_bytes).await?;
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
        let _: usize = self.client.rpush(&subject, items_bytes).await?;
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
        let _: usize = self.client.rpush(&subject, item.encode_queue_item_vec()?).await?;
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
        let items_bytes: Vec<Vec<u8>> = items.iter().map(|x| x.encode_queue_item_vec()).collect::<anyhow::Result<_>>()?;
        let _: usize = self.client.rpush(&subject, items_bytes).await?;
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
        let _: usize = self.client.rpush(&subject, item.encode_queue_item_vec()?).await?;
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
        let items_bytes: Vec<Vec<u8>> = items.into_iter().map(|x| x.encode_queue_item_vec()).collect::<anyhow::Result<_>>()?;
        let _: usize = self.client.rpush(&subject, items_bytes).await?;
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
        let items_bytes: Vec<Vec<u8>> = items.iter().map(|x| x.encode_queue_item_vec()).collect::<anyhow::Result<_>>()?;
        let _: usize = self.client.rpush(&subject, items_bytes).await?;
        Ok(())
    }
}
#[async_trait]
impl QStandardEphemeralQueueSubscriber for StandardRedisStore {
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
        let start = tokio::time::Instant::now();
        let timeout_duration = Duration::from_millis(timeout_ms);
        loop {
            let item: Option<Vec<u8>> = self.client.lpop(&subject, None).await?;
            if let Some(i) = item {
                return Ok(Some(i));
            } else {
                if start.elapsed() >= timeout_duration {
                    return Ok(None);
                }
                sleep(Duration::from_millis(100)).await;
            }
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
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        let start = tokio::time::Instant::now();
        let timeout_duration = Duration::from_millis(timeout_ms);
        loop {
            let item: Option<Vec<u8>> = self.client.lpop(&subject, None).await?;
            if let Some(i) = item {
                return Ok(Some(QK::QueueItem::decode_queue_item_ref(&i)?));
            } else {
                if start.elapsed() >= timeout_duration {
                    return Ok(None);
                }
                sleep(Duration::from_millis(100)).await;
            }
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
        let items: Vec<BulkString> = self.client.lrange(&subject, 0, (max_items as isize) - 1).await?;
        let _: () = self.client.ltrim(&subject, items.len() as isize, -1).await?;
        Ok(items.into_iter().map(|i| i.into()).collect())
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
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        let items: Vec<Vec<u8>> = self.client.lrange(&subject, 0, (max_items as isize) - 1).await?;
        let _: () = self.client.ltrim(&subject, items.len() as isize, -1).await?;
        let result: Vec<QK::QueueItem> = items
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
        let item: Option<Vec<u8>> = self.client.lpop(&subject, None).await?;
        Ok(item)
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
        let item: Option<Vec<u8>> = self.client.lpop(&subject, None).await?;
        if let Some(i) = item {
            Ok(Some(QK::QueueItem::decode_queue_item_ref(&i)?))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl QParthProofStoreReader for StandardRedisStore {
    async fn get_proof_bytes_by_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J, unique_pending_id: u64) -> anyhow::Result<Option<Vec<u8>>> {
        let job_id_bytes = job_id.into().to_vec();
        let bucket = get_tmp_proof_store_bucket_ns_key(&self.root_prefix, self.realm_id, self.realm_sub_id, unique_pending_id);
        let data = self.get_bytes_generic_internal(&bucket, &job_id_bytes).await?;
        if data.is_empty() {
            Ok(None)
        } else {
            Ok(Some(data))
        }
    }
    async fn get_proof_by_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync, P: QPDSerializable>(&self, job_id: J, unique_pending_id: u64) -> anyhow::Result<Option<P>> {
        let job_id_bytes = job_id.into().to_vec();
        let bucket = get_tmp_proof_store_bucket_ns_key(&self.root_prefix, self.realm_id, self.realm_sub_id, unique_pending_id);
        let data = self.get_bytes_generic_internal(&bucket, &job_id_bytes).await?;
        if data.is_empty() {
            Ok(None)
        } else {
            let proof: P = P::from_bytes(&data)?;
            Ok(Some(proof))
        }
    }
    async fn contains_proof_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J, unique_pending_id: u64) -> anyhow::Result<bool> {
        let job_id_bytes = job_id.into().to_vec();
        let bucket = get_tmp_proof_store_bucket_ns_key(&self.root_prefix, self.realm_id, self.realm_sub_id, unique_pending_id);
        let data = self.get_bytes_generic_internal(&bucket, &job_id_bytes).await?;
        Ok(!data.is_empty())
    }
}

#[async_trait]
impl QParthProofStoreWriter for StandardRedisStore {
    async fn put_proof_bytes_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J, unique_pending_id: u64, proof_bytes: &[u8]) -> anyhow::Result<()> {
        let job_id_bytes = job_id.into().to_vec();
        let bucket = get_tmp_proof_store_bucket_ns_key(&self.root_prefix, self.realm_id, self.realm_sub_id, unique_pending_id);
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
        let mut client = self.client.clone();
        let bucket = get_tmp_proof_store_bucket_ns_key(&self.root_prefix, self.realm_id, self.realm_sub_id, unique_pending_id);
        let _: usize = client.del(&bucket).await?;
        Ok(())
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
    async fn qtdb_raw_kv_get_many_values_vec_owned(&self, keys: Vec<Vec<u8>>) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let data = self.get_many_bytes_generic_internal(&self.kv_store_namespace, &keys).await?;
        Ok(data.into_iter().map(|v| if v.is_empty() { None } else { Some(v) }).collect())
    }

    async fn qtdb_raw_kv_get_many_values(&self, keys: &[&[u8]]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let data = self.get_many_bytes_generic_internal_ref(&self.kv_store_namespace, keys).await?;
        Ok(data.into_iter().map(|v| if v.is_empty() { None } else { Some(v) }).collect())
    }
    async fn qtdb_raw_kv_get_many_values_vec(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
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
    async fn qtdb_raw_kv_put_value(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        self.set_bytes_generic_internal(&self.kv_store_namespace, key, value).await
    }
    async fn qtdb_raw_kv_delete_key(&self, key: &[u8]) -> anyhow::Result<()> {
        let _: usize = self.client.hdel(&self.kv_store_namespace, key).await?;
        Ok(())
    }
    async fn qtdb_raw_kv_put_many_values(&self, entries: &[QPDPair<Vec<u8>, Vec<u8>>]) -> anyhow::Result<()> {
        self.set_many_bytes_generic_internal_ref(&self.kv_store_namespace, entries).await
    }
    async fn qtdb_raw_kv_put_many_values_tuple(&self, entries: &[(Vec<u8>, Vec<u8>)]) -> anyhow::Result<()> {
        self.set_many_bytes_generic_internal_tuple(&self.kv_store_namespace, entries).await
    }

    async fn qtdb_raw_kv_put_many_values_tuple_ref<'a>(&self, entries: &[(&'a [u8], &'a [u8])]) -> anyhow::Result<()> {
        let _: usize = self.client.hset(&self.kv_store_namespace, entries).await?;
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
        let mut entries: Vec<(&[u8], &[u8])> = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let start = i * combined_size;
            let key = &data[start..start + KEY_SIZE];
            let value = &data[start + KEY_SIZE..start + combined_size];
            entries.push((key, value));
        }
        let _: usize = self.client.hset(&self.kv_store_namespace, entries).await?;
        Ok(())
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
    async fn qtdb_raw_counter_increment_by(&self, key: &[u8], increment_by: i64) -> anyhow::Result<i64> {
        let new_value = self.inc_iu64_generic_internal(&self.kv_store_namespace, key, increment_by).await?;
        Ok(new_value as i64)
    }
    async fn qtdb_raw_counter_set_value(&self, key: &[u8], value: i64) -> anyhow::Result<()> {
        self.set_iu64_generic_internal(&self.kv_store_namespace, key, value).await
    }
}

impl QAutoImplementGeneric for StandardRedisStore {}
