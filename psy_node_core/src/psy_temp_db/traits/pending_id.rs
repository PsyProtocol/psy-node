use async_trait::async_trait;
use auto_impl::auto_impl;
use parth_core::{node::realm_identifier::QRealmIdentifier, QCoreProcCheckpointUniqueId};


#[async_trait]
#[auto_impl(&, Arc)]
pub trait QTempDBPendingIdReader {
    async fn get_unique_pending_id(&self, rid: &QRealmIdentifier) -> anyhow::Result<u64>;
    async fn get_proc_checkpoint_unique_id(&self, rid: &QRealmIdentifier) -> anyhow::Result<QCoreProcCheckpointUniqueId>;
    async fn get_unique_pending_ids(&self, rid: &QRealmIdentifier) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)>;   
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait QTempDBPendingIdWriter {
    async fn set_unique_pending_ids(&self, rid: &QRealmIdentifier, unique_pending_id: u64, proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId) -> anyhow::Result<()>;
}

pub trait QTempDBPendingIdStore: QTempDBPendingIdReader + QTempDBPendingIdWriter {}
impl<T: QTempDBPendingIdReader + QTempDBPendingIdWriter> QTempDBPendingIdStore for T {}





