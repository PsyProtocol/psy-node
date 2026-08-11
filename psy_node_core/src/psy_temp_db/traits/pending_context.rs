use async_trait::async_trait;
use parth_core::{node::realm_identifier::QRealmIdentifier, protocol::core_types::Q256BitHash};
use psy_data::protocol::chain_context::{AuthorityScope, PendingContext};

use crate::store::pending_generation_identity::PendingGenerationContext;

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

    /// Resolve the atomically published context for a producer that still
    /// carries the processing pending ID in its local state. There is no
    /// legacy-key fallback: missing context or any pending mismatch fails
    /// closed before a V2 proof-work key can be constructed.
    async fn require_pending_context_for_pending_id(
        &self,
        rid: &QRealmIdentifier,
        expected_unique_pending_id: u64,
    ) -> anyhow::Result<PendingContext<Hash>> {
        let context = self
            .get_current_pending_context(rid)
            .await?
            .ok_or_else(|| anyhow::anyhow!("current pending context is unavailable"))?;
        if context.unique_pending_id().get() != expected_unique_pending_id {
            anyhow::bail!(
                "current pending context ID {} does not match producer ID {}",
                context.unique_pending_id().get(),
                expected_unique_pending_id
            );
        }
        Ok(context)
    }

    /// Resolve one exact durable processing namespace.
    ///
    /// A pending ID alone is not sufficient: the same numeric pending ID can
    /// otherwise select a stale proc-checkpoint proof namespace. Realm
    /// identity is checked at the same boundary so a context stored under the
    /// wrong authority cannot be used to construct proof-work keys.
    async fn require_pending_context_for_generation(
        &self,
        rid: &QRealmIdentifier,
        expected: PendingGenerationContext,
    ) -> anyhow::Result<PendingContext<Hash>> {
        let context = self
            .require_pending_context_for_pending_id(rid, expected.pending_id().get())
            .await?;
        if context.proc_checkpoint_unique_id().as_u128()
            != expected.proc_checkpoint_id().as_u128()
        {
            anyhow::bail!(
                "current pending context proc ID {} does not match durable processing proc ID {}",
                context.proc_checkpoint_unique_id().as_u128(),
                expected.proc_checkpoint_id().as_u128(),
            );
        }
        if context.authority()
            != (AuthorityScope::Realm {
                realm_id: rid.realm_id,
                realm_sub_id: rid.realm_sub_id,
            })
        {
            anyhow::bail!("current pending context authority does not match realm identifier");
        }
        Ok(context)
    }
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
