use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;


#[async_trait]
pub trait QTempDBUserContractUpdatesReader {
    async fn get_contract_updates_for_user(&self, rid: &QRealmIdentifier, unique_pending_id: u64, user_id: u64) -> anyhow::Result<Option<Vec<u8>>>;
}

#[async_trait]
pub trait QTempDBUserContractUpdatesWriter {
    async fn set_contract_updates_for_user(&self, rid: &QRealmIdentifier, unique_pending_id: u64, user_id: u64, data: Vec<u8>) -> anyhow::Result<()>;
    async fn set_contract_updates_for_user_ref(&self, rid: &QRealmIdentifier, unique_pending_id: u64, user_id: u64, data: &[u8]) -> anyhow::Result<()>;
}

pub trait QTempDBUserContractUpdatesStore: QTempDBUserContractUpdatesReader + QTempDBUserContractUpdatesWriter {}
impl<T: QTempDBUserContractUpdatesReader + QTempDBUserContractUpdatesWriter> QTempDBUserContractUpdatesStore for T {}
