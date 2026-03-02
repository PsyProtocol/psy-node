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

pub trait QTempDBWorkerReputationStore: QTempDBWorkerReputationReader + QTempDBWorkerReputationWriter {}
impl<T: QTempDBWorkerReputationReader + QTempDBWorkerReputationWriter> QTempDBWorkerReputationStore for T {}
