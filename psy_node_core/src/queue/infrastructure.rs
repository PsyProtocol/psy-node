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

    /// Reset any per-consumer ack/offset state for this unique_id and recreate the consumer.
    ///
    /// On JetStream this deletes and recreates the consumer so a fresh `DeliverPolicy::All`
    /// pass replays every message still in the stream — needed for crash recovery when the
    /// previous instance of this gatherer cycle ack'd messages but never committed them to
    /// the database. Backends without per-consumer ack state can keep the default no-op.
    async fn recreate_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
    ) -> anyhow::Result<()> {
        self.ensure_consumer(queue_key, realm_id, realm_sub_id, unique_id, task_group).await
    }
}
