//! The commit-time half of the verification journal (design-r1 §2.2.2).
//!
//! The implementation is a storage concern, but `commit_state` is generic over
//! the store and cannot name a driver type, so the capability arrives as a trait
//! the same way the rest of the recording does.
//!
//! It is an `Option` on the recording, and that is the one place in this design
//! where optionality is correct: the journal takes part in no delete decision, so
//! its absence loses verification and never leaves a manifest incomplete.  What
//! §0.2 D3 forbids is optional *recording*, which is a different thing and stays
//! mandatory.

use async_trait::async_trait;

/// Observes recorded keys before and after the commit that writes them.
#[async_trait]
pub trait CommitVerificationJournal: Send + Sync {
    /// Called before any state write, because tables without a version axis are
    /// overwritten in place and their previous value then exists nowhere.
    async fn record_before(
        &self,
        checkpoint_id: u64,
        chain_epoch: u64,
        planned: &[(u16, Vec<u8>)],
    ) -> anyhow::Result<()>;

    /// Called once the state writes have landed.
    async fn record_after(
        &self,
        checkpoint_id: u64,
        chain_epoch: u64,
        planned: &[(u16, Vec<u8>)],
    ) -> anyhow::Result<()>;

    /// What was observed at one checkpoint, as `(physical_table, locator,
    /// before_image)` for the keys that existed before that commit wrote them.
    ///
    /// Reading is part of the contract now, not a convenience.  A rollback
    /// restores a rewritten row from the image recorded here, so the journal has
    /// stopped being evidence a deployment may decline to keep: without it there
    /// is no way to tell a row the discarded range *created* -- which must stay
    /// deleted -- from one it *rewrote*, whose previous value exists nowhere
    /// else.
    ///
    /// Only rows whose previous value lived in the row itself are returned:
    /// those with a before image and no recorded version.  A version is recorded
    /// exactly when the table has a version axis, and there the earlier value is
    /// a separate row the rollback leaves standing -- putting it back at the
    /// discarded locator would rebuild a version the chain no longer has.  Rows
    /// with no before image at all were created by the discarded range and are
    /// right to stay deleted.
    async fn rewritten_before_images(
        &self,
        checkpoint_id: u64,
        chain_epoch: u64,
    ) -> anyhow::Result<Vec<(u16, Vec<u8>, Vec<u8>)>>;
}
