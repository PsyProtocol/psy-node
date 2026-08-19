//! What epoch a Realm's cached view of the chain was built under.
//!
//! One row per Realm, written only when the epoch changes -- which is once per
//! rollback -- so keeping it costs nothing while the chain runs normally.
//!
//! ## Why the height is not enough
//!
//! A Realm can already compare its cached head against the head the Coordinator
//! publishes, and that catches a rollback it comes back to immediately.  It
//! stops working as soon as the Coordinator has produced past the old head
//! again: the heights agree, and only the *contents* of the checkpoints in
//! between differ.  Nothing in a height comparison can see that.
//!
//! The epoch can, because it advances if and only if a rollback published one,
//! and it is carried on the head the Coordinator publishes.  A Realm that
//! recorded the epoch it synced under can ask the question at any time, however
//! late, without having watched the rollback happen.
//!
//! ## Why the epoch alone is still not enough
//!
//! It says a rollback happened, not where the discarded branch began -- and by
//! the time a Realm looks, the Coordinator has usually produced past that point,
//! so the published head does not say either.  That is what the rollback history
//! is for: the lowest target across the rollbacks the Realm missed is the height
//! above which everything it still holds belongs to a branch that no longer
//! exists.

/// The epoch a Realm believes it is synced under.
#[async_trait::async_trait]
pub trait RealmSyncEpochStore: Send + Sync {
    /// `None` when this Realm has never recorded one, which is a Realm that has
    /// not yet synced rather than one at epoch zero.  The distinction matters:
    /// a fresh Realm has no stale cache to reconcile, and treating it as if it
    /// had would truncate a chain that was never rolled back.
    async fn read_synced_epoch(&self) -> anyhow::Result<Option<u64>>;

    async fn write_synced_epoch(&self, chain_epoch: u64) -> anyhow::Result<()>;
}
