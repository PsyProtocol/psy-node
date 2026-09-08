use async_trait::async_trait;
use parth_core::{node::realm_identifier::QRealmIdentifier, QCoreProcCheckpointUniqueId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatheringGeneration {
    pub checkpoint_id: u64,
    pub unique_pending_id: u64,
    pub proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
}

#[async_trait]
pub trait QTempDBPendingIdReader {
    async fn get_unique_pending_ids(&self, rid: &QRealmIdentifier) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)>;
    async fn get_gathering_generation(&self, rid: &QRealmIdentifier) -> anyhow::Result<GatheringGeneration>;
}

#[async_trait]
pub trait QTempDBPendingIdWriter {
    async fn set_unique_pending_ids(&self, rid: &QRealmIdentifier, unique_pending_id: u64, proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId) -> anyhow::Result<()>;
    async fn set_gathering_generation(&self, rid: &QRealmIdentifier, generation: GatheringGeneration) -> anyhow::Result<()>;
}

pub trait QTempDBPendingIdStore: QTempDBPendingIdReader + QTempDBPendingIdWriter {}
impl<T: QTempDBPendingIdReader + QTempDBPendingIdWriter> QTempDBPendingIdStore for T {}





