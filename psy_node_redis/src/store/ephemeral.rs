/*use async_trait::async_trait;
use parth_core::data::queue::queue_key::PCoreStandardQueueKeyForRealm;
use psy_node_core::queue::ephemeral::{QStandardEphemeralQueuePublisher, QStandardEphemeralQueueSubscriber};

use crate::store::StandardRedisStore;
#[async_trait]
impl QStandardEphemeralQueuePublisher for StandardRedisStore {
    async fn publish_ephemeral_queue_item_bytes_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        item_bytes: &[u8],
    ) -> anyhow::Result<()> {
        todo!()
    }
    async fn publish_many_ephemeral_queue_items_bytes_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &[QK],
        items_bytes: &[&[u8]],
    ) -> anyhow::Result<()> {
        todo!()
    }
    async fn publish_ephemeral_queue_item_owned_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        item_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        todo!()
    }
    async fn publish_many_ephemeral_queue_items_owned_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &[QK],
        items_bytes: Vec<Vec<u8>>,
    ) -> anyhow::Result<()> {
        todo!()
    }
    async fn publish_ephemeral_queue_item_ref<QK: PCoreStandardQueueKeyForRealm>(&self, queue_key: &QK, item: &QK::QueueItem) -> anyhow::Result<()> {
        todo!()
    }
    async fn publish_many_ephemeral_queue_items_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &[QK],
        items: &[&QK::QueueItem],
    ) -> anyhow::Result<()> {
        todo!()
    }
    async fn publish_ephemeral_queue_item_owned<QK: PCoreStandardQueueKeyForRealm>(&self, queue_key: &QK, item: QK::QueueItem) -> anyhow::Result<()> {
        todo!()
    }
    async fn publish_many_ephemeral_queue_items_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &[QK],
        items: Vec<QK::QueueItem>,
    ) -> anyhow::Result<()> {
        todo!()
    }
}

#[async_trait]
impl QStandardEphemeralQueueSubscriber for StandardRedisStore {
    async fn wait_for_ephemeral_queue_item_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        todo!()
    }
    async fn wait_for_ephemeral_queue_item<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        timeout_ms: u64,
    ) -> anyhow::Result<QK::QueueItem> {
        todo!()
    }
    async fn dump_entire_ephemeral_queue_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        max_items: usize,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        todo!()
    }
    async fn dump_entire_ephemeral_queue<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        max_items: usize,
    ) -> anyhow::Result<Vec<QK::QueueItem>> {
        todo!()
    }
    async fn consume_ephemeral_queue_item_or_none_bytes<QK: PCoreStandardQueueKeyForRealm>(&self, queue_key: &QK) -> anyhow::Result<Option<Vec<u8>>> {
        todo!()
    }
    async fn consume_ephemeral_queue_item_or_none<QK: PCoreStandardQueueKeyForRealm>(&self, queue_key: &QK) -> anyhow::Result<Option<QK::QueueItem>> {
        todo!()
    }
}
*/