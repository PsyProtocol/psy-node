use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;

#[async_trait]
pub trait QTempDBSubmitStatusReader {
    async fn get_submitted_status_for_pending(&self, rid: &QRealmIdentifier, unique_pending_id: u64, user_or_realm_id: u64) -> anyhow::Result<u64>;
}

#[async_trait]
pub trait QTempDBSubmitStatusWriter {
    async fn set_submitted_status_for_pending(&self, rid: &QRealmIdentifier, unique_pending_id: u64, user_or_realm_id: u64, status: u64) -> anyhow::Result<()>;
}

pub trait QTempDBSubmitStatusStore: QTempDBSubmitStatusReader + QTempDBSubmitStatusWriter {}
impl<T: QTempDBSubmitStatusReader + QTempDBSubmitStatusWriter> QTempDBSubmitStatusStore for T {}





