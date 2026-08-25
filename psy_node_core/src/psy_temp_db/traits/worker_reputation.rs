use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;

#[async_trait]
pub trait QTempDBWorkerReputationReader {
    async fn get_worker_reputation(&self, rid: &QRealmIdentifier, public_key: &[u8; 33]) -> anyhow::Result<u64>;
}

#[async_trait]
pub trait QTempDBWorkerReputationWriter {
    async fn set_worker_reputation(
        &self,
        rid: &QRealmIdentifier,
        public_key: &[u8; 33],
        reputation: u64,
    ) -> anyhow::Result<()>;
}

#[async_trait]
pub trait QTempDBWorkerReputationMutation {
    async fn apply_worker_reputation_once(
        &self,
        rid: &QRealmIdentifier,
        public_key: &[u8; 33],
        unique_pending_id: u64,
        job_id: &[u8; 24],
        on_time: bool,
        reward: u64,
        slash: u64,
        maximum: u64,
    ) -> anyhow::Result<bool>;
}

pub trait QTempDBWorkerReputationStore:
    QTempDBWorkerReputationReader + QTempDBWorkerReputationWriter + QTempDBWorkerReputationMutation
{
}
impl<T: QTempDBWorkerReputationReader + QTempDBWorkerReputationWriter + QTempDBWorkerReputationMutation>
    QTempDBWorkerReputationStore for T
{
}
