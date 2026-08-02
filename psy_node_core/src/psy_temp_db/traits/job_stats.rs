use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;

/// Aggregated worker job statistics stored under one unique pending ID.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckpointJobStats {
    pub total_completed: u64,
    pub total_duration_ms: u64,
    pub min_duration_ms: Option<u64>,
    pub max_duration_ms: Option<u64>,
}

/// Persistent counters used by edge nodes to expose checkpoint proof metrics.
#[async_trait]
pub trait QTempDBJobStatsStore: Send + Sync {
    async fn increment_job_stats(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        duration_ms: u64,
    ) -> anyhow::Result<()>;

    async fn get_job_stats(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
    ) -> anyhow::Result<Option<CheckpointJobStats>>;

    async fn clear_job_stats(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
    ) -> anyhow::Result<()>;
}
