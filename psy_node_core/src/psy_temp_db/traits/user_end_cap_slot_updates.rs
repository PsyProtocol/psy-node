use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;

#[async_trait]
pub trait QTempDBUserEndCapSlotUpdatesReader {
    async fn get_user_end_cap_slot_updates(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        user_id: u64,
    ) -> anyhow::Result<Option<Vec<u8>>>;
}

#[async_trait]
pub trait QTempDBUserEndCapSlotUpdatesWriter {
    async fn set_user_end_cap_slot_updates(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        user_id: u64,
        data: Vec<u8>,
    ) -> anyhow::Result<()>;

    async fn set_user_end_cap_slot_updates_ref(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        user_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()>;
}

pub trait QTempDBUserEndCapSlotUpdatesStore:
    QTempDBUserEndCapSlotUpdatesReader + QTempDBUserEndCapSlotUpdatesWriter
{
}

impl<T: QTempDBUserEndCapSlotUpdatesReader + QTempDBUserEndCapSlotUpdatesWriter>
    QTempDBUserEndCapSlotUpdatesStore for T
{
}
