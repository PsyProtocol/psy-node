use async_trait::async_trait;
use parth_core::{data::queue::queue_key::{PCoreStandardQueueKeyForRealm, QPBaseQueueType}, QCoreProcCheckpointUniqueId};

#[async_trait]
pub trait QStandardQueueBase {
    async fn ensure_stream(&self) -> anyhow::Result<()>;

    async fn ensure_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
    ) -> anyhow::Result<()>;

    async fn ensure_stream_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
    ) -> anyhow::Result<()> {
        self.ensure_stream().await?;
        self.ensure_consumer(queue_key, realm_id, realm_sub_id, unique_id, task_group).await
    }
}
