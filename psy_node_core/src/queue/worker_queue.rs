use async_trait::async_trait;
use parth_core::{data::queue::queue_key::PCoreStandardQueueKeyForRealm, QCoreProcCheckpointUniqueId};
use super::infrastructure::QStandardQueueBase;

pub trait QStandardWorkerQueue: QStandardQueueBase {
    type PublishBarrier: std::fmt::Debug + Send + Sync;
}

#[async_trait]
pub trait QStandardWorkerQueuePublisher: QStandardWorkerQueue {
    async fn publish_worker_queue_item_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item: &QK::QueueItem,
    ) -> anyhow::Result<Self::PublishBarrier>;
    async fn publish_many_worker_queue_items_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: &[&QK::QueueItem],
    ) -> anyhow::Result<Self::PublishBarrier>;
    async fn publish_worker_queue_item_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item: QK::QueueItem,
    ) -> anyhow::Result<Self::PublishBarrier>;
    async fn publish_many_worker_queue_items_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: Vec<QK::QueueItem>,
    ) -> anyhow::Result<Self::PublishBarrier>;
    async fn publish_many_worker_queue_items<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: &[QK::QueueItem],
    ) -> anyhow::Result<Self::PublishBarrier>;
}

#[async_trait]
pub trait QStandardWorkerQueueSubscriber: QStandardWorkerQueue {
    async fn wait_for_worker_queue_item<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        timeout_ms: u64,
    ) -> anyhow::Result<Option<QK::QueueItem>>;
    async fn dump_entire_worker_queue<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        max_items: usize,
    ) -> anyhow::Result<Vec<QK::QueueItem>>;
    async fn get_next_worker_queue_item_or_none<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
    ) -> anyhow::Result<Option<QK::QueueItem>>;
    async fn wait_until_all_jobs_complete_or_timeout_worker<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_topic: u128,
        task_group: u32,
        barrier: &Self::PublishBarrier,
        timeout_ms: u64,
    ) -> anyhow::Result<()>;

    async fn worker_queue_report_job_completed<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_topic: u128,
        task_group: u32,
        item: &QK::QueueItem,
    ) -> anyhow::Result<bool>;

    async fn delete_worker_queue_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_topic: u128,
        _task_group: u32,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}
