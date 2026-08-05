use async_trait::async_trait;
use parth_core::{node::realm_identifier::QRealmIdentifier, protocol::core_types::Q256BitHash};
use psy_data::protocol::chain_context::PendingContext;

/// Atomic current-work namespace observed by Edge.
///
/// Unlike the legacy pending-ID tuple, this value binds pending/proc IDs to an
/// exact canonical branch and authority in one raw-KV value.
#[async_trait]
pub trait QTempDBPendingContextReader<Hash: Q256BitHash> {
    async fn get_current_pending_context(
        &self,
        rid: &QRealmIdentifier,
    ) -> anyhow::Result<Option<PendingContext<Hash>>>;
}

#[async_trait]
pub trait QTempDBPendingContextWriter<Hash: Q256BitHash> {
    async fn set_current_pending_context(
        &self,
        rid: &QRealmIdentifier,
        context: &PendingContext<Hash>,
    ) -> anyhow::Result<()>;
}

#[async_trait]
pub trait QTempDBPendingContextCleaner {
    /// Remove the published context while no canonical authority exists.
    ///
    /// In particular, startup must not leave a context from an older database
    /// incarnation visible while Coordinator is waiting for genesis.
    async fn clear_current_pending_context(
        &self,
        rid: &QRealmIdentifier,
    ) -> anyhow::Result<()>;
}

pub trait QTempDBPendingContextStore<Hash: Q256BitHash>:
    QTempDBPendingContextReader<Hash>
    + QTempDBPendingContextWriter<Hash>
    + QTempDBPendingContextCleaner
{
}

impl<T, Hash> QTempDBPendingContextStore<Hash> for T
where
    Hash: Q256BitHash,
    T: QTempDBPendingContextReader<Hash>
        + QTempDBPendingContextWriter<Hash>
        + QTempDBPendingContextCleaner,
{
}
