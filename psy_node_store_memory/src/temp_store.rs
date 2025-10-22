use std::{collections::VecDeque, sync::Arc, time::Duration};

use async_trait::async_trait;
use dashmap::DashMap;
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
        temp_db::{QTempDatabaseRawCounterReaderBase, QTempDatabaseRawCounterWriterBase, QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase},
    },
};
use tokio::sync::{Mutex, Notify};

/// A single MPMC (Multi-Producer, Multi-Consumer) async queue.
#[derive(Debug, Default)]
struct Queue {
    items: Mutex<VecDeque<Vec<u8>>>,
    notify: Notify,
}

/// An in-memory, async-safe implementation of the data stores and queues,
/// mirroring the `StandardRedisStore` interface. This is useful for testing
/// and development environments.
#[derive(Debug, Clone)]
pub struct InMemoryTempStore {
    /// Mimics the Redis HASH for proofs. Stores job_id -> proof_bytes.
    proof_store: Arc<DashMap<Vec<u8>, Vec<u8>>>,
    /// Mimics the Redis HASH for KV pairs.
    kv_store: Arc<DashMap<Vec<u8>, Vec<u8>>>,
    /// Mimics the Redis HASH for counters, using i64 for efficiency.
    counter_store: Arc<DashMap<Vec<u8>, i64>>,
    /// Mimics Redis LISTs for queues, keyed by a unique subject string.
    queues: Arc<DashMap<String, Arc<Queue>>>,
    /// Root prefix, used for generating queue subject names.
    pub root_prefix: String,
    /// Realm ID, used for generating queue subject names.
    pub realm_id: u64,
    /// Realm Sub ID, used for generating queue subject names.
    pub realm_sub_id: u64,
}

impl InMemoryTempStore {
    /// Creates a new, empty `InMemoryTempStore`.
    ///
    /// # Arguments
    ///
    /// * `root_prefix` - A prefix used in generating queue subjects to ensure uniqueness.
    /// * `realm_id` - The primary realm identifier.
    /// * `realm_sub_id` - The secondary realm identifier.
    pub fn new(root_prefix: String, realm_id: u64, realm_sub_id: u64) -> Self {
        Self {
            proof_store: Arc::new(DashMap::new()),
            kv_store: Arc::new(DashMap::new()),
            counter_store: Arc::new(DashMap::new()),
            queues: Arc::new(DashMap::new()),
            root_prefix,
            realm_id,
            realm_sub_id,
        }
    }

    /// Helper to atomically get or create a queue handle.
    fn get_or_create_queue(&self, subject: &str) -> Arc<Queue> {
        self.queues.entry(subject.to_string()).or_default().clone()
    }
}

#[async_trait]
impl QStandardEphemeralQueuePublisher for InMemoryTempStore {
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
        let queue_handle = self.get_or_create_queue(&subject);

        let mut queue = queue_handle.items.lock().await;
        queue.push_back(item_bytes.to_vec());
        queue_handle.notify.notify_one();

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
        if items_bytes.is_empty() {
            return Ok(());
        }
        let subject = queue_key.get_queue_subject(&self.root_prefix, realm_id, realm_sub_id, unique_id, task_group);
        let queue_handle = self.get_or_create_queue(&subject);

        let mut queue = queue_handle.items.lock().await;
        for item in items_bytes {
            queue.push_back(item.to_vec());
        }
        // CORRECTED: Use notify_waiters() to wake all consumers when multiple items are added.
        queue_handle.notify.notify_waiters();

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
        self.publish_ephemeral_queue_item_bytes_ref(queue_key, realm_id, realm_sub_id, unique_id, task_group, &item_bytes).await
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
        let refs: Vec<&[u8]> = items_bytes.iter().map(|v| v.as_slice()).collect();
        self.publish_many_ephemeral_queue_items_bytes_ref(queue_key, realm_id, realm_sub_id, unique_id, task_group, &refs).await
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
        let bytes = item.encode_queue_item_vec()?;
        self.publish_ephemeral_queue_item_bytes_ref(queue_key, realm_id, realm_sub_id, unique_id, task_group, &bytes).await
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
        let bytes_vec: anyhow::Result<Vec<Vec<u8>>> = items.iter().map(|item| item.encode_queue_item_vec()).collect();
        self.publish_many_ephemeral_queue_items_owned_bytes(queue_key, realm_id, realm_sub_id, unique_id, task_group, bytes_vec?).await
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
        self.publish_ephemeral_queue_item_ref(queue_key, realm_id, realm_sub_id, unique_id, task_group, &item).await
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
        let refs: Vec<&QK::QueueItem> = items.iter().collect();
        self.publish_many_ephemeral_queue_items_ref(queue_key, realm_id, realm_sub_id, unique_id, task_group, &refs).await
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
        let refs: Vec<&QK::QueueItem> = items.iter().collect();
        self.publish_many_ephemeral_queue_items_ref(queue_key, realm_id, realm_sub_id, unique_id, task_group, &refs).await
    }
}

#[async_trait]
impl QStandardEphemeralQueueSubscriber for InMemoryTempStore {
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
        let queue_handle = self.get_or_create_queue(&subject);
        let timeout_duration = Duration::from_millis(timeout_ms);

        match tokio::time::timeout(timeout_duration, async {
            loop {
                // Attempt to pop an item.
                let mut queue = queue_handle.items.lock().await;
                if let Some(item) = queue.pop_front() {
                    return item;
                }
                // If empty, prepare to wait for a notification.
                let notified = queue_handle.notify.notified();
                drop(queue); // Release the lock before waiting.
                notified.await;
            }
        })
        .await
        {
            Ok(item) => Ok(Some(item)),
            Err(_) => { // TimeoutError
                // After a timeout, perform one last check in case an item arrived
                // just as the timeout occurred.
                let mut queue = queue_handle.items.lock().await;
                Ok(queue.pop_front())
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
        if let Some(bytes) = self.wait_for_ephemeral_queue_item_bytes(queue_key, realm_id, realm_sub_id, unique_id, task_group, timeout_ms).await? {
            Ok(Some(QK::QueueItem::decode_queue_item_ref(&bytes)?))
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
        let queue_handle = self.get_or_create_queue(&subject);
        let mut queue = queue_handle.items.lock().await;

        let count = std::cmp::min(queue.len(), max_items);
        let items = queue.drain(..count).collect();
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
        let bytes_vec = self.dump_entire_ephemeral_queue_bytes(queue_key, realm_id, realm_sub_id, unique_id, task_group, max_items).await?;
        bytes_vec.into_iter().map(|bytes| QK::QueueItem::decode_queue_item_ref(&bytes)).collect()
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
        let queue_handle = self.get_or_create_queue(&subject);
        let mut queue = queue_handle.items.lock().await;
        Ok(queue.pop_front())
    }

    async fn consume_ephemeral_queue_item_or_none<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
    ) -> anyhow::Result<Option<QK::QueueItem>> {
        if let Some(bytes) = self.consume_ephemeral_queue_item_or_none_bytes(queue_key, realm_id, realm_sub_id, unique_id, task_group).await? {
            Ok(Some(QK::QueueItem::decode_queue_item_ref(&bytes)?))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl QParthProofStoreReader for InMemoryTempStore {
    async fn get_proof_bytes_by_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J) -> anyhow::Result<Option<Vec<u8>>> {
        let job_id_bytes = job_id.into().to_vec();
        Ok(self.proof_store.get(&job_id_bytes).map(|r| r.value().clone()))
    }

    async fn get_proof_by_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync, P: QPDSerializable>(&self, job_id: J) -> anyhow::Result<Option<P>> {
        match self.get_proof_bytes_by_job_id(job_id).await? {
            Some(bytes) => Ok(Some(P::from_bytes(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn contains_proof_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J) -> anyhow::Result<bool> {
        let job_id_bytes = job_id.into().to_vec();
        Ok(self.proof_store.contains_key(&job_id_bytes))
    }
}

#[async_trait]
impl QParthProofStoreWriter for InMemoryTempStore {
    async fn put_proof_bytes_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J, proof_bytes: &[u8]) -> anyhow::Result<()> {
        let job_id_bytes = job_id.into().to_vec();
        self.proof_store.insert(job_id_bytes, proof_bytes.to_vec());
        Ok(())
    }

    async fn put_proof_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync, P: QPDSerializable + Send + Sync>(&self, job_id: J, proof: &P) -> anyhow::Result<()> {
        let proof_bytes = proof.to_bytes()?;
        self.put_proof_bytes_for_job_id(job_id, &proof_bytes).await
    }
}

#[async_trait]
impl QTempDatabaseRawKVReaderBase for InMemoryTempStore {
    async fn qtdb_raw_kv_get_value(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.kv_store.get(key).map(|r| r.value().clone()))
    }
    
    async fn qtdb_raw_kv_get_many_values_vec_owned(&self, keys: Vec<Vec<u8>>) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let result = keys.iter().map(|key| self.kv_store.get(key).map(|r| r.value().clone())).collect();
        Ok(result)
    }

    async fn qtdb_raw_kv_get_many_values(&self, keys: &[&[u8]]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let result = keys.iter().map(|key| self.kv_store.get(*key).map(|r| r.value().clone())).collect();
        Ok(result)
    }

    async fn qtdb_raw_kv_get_many_values_vec(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let result = keys.iter().map(|key| self.kv_store.get(key).map(|r| r.value().clone())).collect();
        Ok(result)
    }

    async fn qtdb_raw_kv_contains_key(&self, key: &[u8]) -> anyhow::Result<bool> {
        Ok(self.kv_store.contains_key(key))
    }
}

#[async_trait]
impl QTempDatabaseRawKVWriterBase for InMemoryTempStore {
    async fn qtdb_raw_kv_put_value(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        self.kv_store.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    async fn qtdb_raw_kv_delete_key(&self, key: &[u8]) -> anyhow::Result<()> {
        self.kv_store.remove(key);
        Ok(())
    }

    async fn qtdb_raw_kv_put_many_values(&self, entries: &[QPDPair<Vec<u8>, Vec<u8>>]) -> anyhow::Result<()> {
        for entry in entries {
            self.kv_store.insert(entry.key.clone(), entry.value.clone());
        }
        Ok(())
    }

    async fn qtdb_raw_kv_put_many_values_tuple(&self, entries: &[(Vec<u8>, Vec<u8>)]) -> anyhow::Result<()> {
        for (key, value) in entries {
            self.kv_store.insert(key.clone(), value.clone());
        }
        Ok(())
    }

    async fn qtdb_raw_kv_put_many_values_tuple_ref<'a>(&self, entries: &[(&'a [u8], &'a [u8])]) -> anyhow::Result<()> {
        for (key, value) in entries {
            self.kv_store.insert(key.to_vec(), value.to_vec());
        }
        Ok(())
    }

    async fn qtdb_raw_kv_put_many_values_tuple_owned(&self, entries: Vec<(Vec<u8>, Vec<u8>)>) -> anyhow::Result<()> {
        for (key, value) in entries {
            self.kv_store.insert(key, value);
        }
        Ok(())
    }

    async fn qtdb_raw_kv_put_many_values_buffer<const KEY_SIZE: usize, const VALUE_SIZE: usize>(&self, data: &[u8]) -> anyhow::Result<()> {
        let combined_size: usize = KEY_SIZE + VALUE_SIZE;
        if data.len() % combined_size != 0 {
            return Err(anyhow::anyhow!("Data length is not a multiple of combined key and value size"));
        }
        if data.is_empty() {
            return Ok(());
        }
        for chunk in data.chunks_exact(combined_size) {
            let (key, value) = chunk.split_at(KEY_SIZE);
            self.kv_store.insert(key.to_vec(), value.to_vec());
        }
        Ok(())
    }
}

#[async_trait]
impl QTempDatabaseRawCounterReaderBase for InMemoryTempStore {
    async fn qtdb_raw_counter_get_value(&self, key: &[u8]) -> anyhow::Result<i64> {
        let value = self.counter_store.get(key).map_or(0, |r| *r.value());
        Ok(value)
    }
}

#[async_trait]
impl QTempDatabaseRawCounterWriterBase for InMemoryTempStore {
    async fn qtdb_raw_counter_increment_by(&self, key: &[u8], increment_by: i64) -> anyhow::Result<i64> {
        // DashMap's entry API provides atomic read-modify-write
        let mut entry = self.counter_store.entry(key.to_vec()).or_insert(0);
        *entry += increment_by;
        Ok(*entry)
    }

    async fn qtdb_raw_counter_set_value(&self, key: &[u8], value: i64) -> anyhow::Result<()> {
        self.counter_store.insert(key.to_vec(), value);
        Ok(())
    }
}

impl QAutoImplementGeneric for InMemoryTempStore {}