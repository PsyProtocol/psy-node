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
        planned: &[(u16, Vec<u8>)],
    ) -> anyhow::Result<()>;

    /// Called once the state writes have landed.
    async fn record_after(
        &self,
        checkpoint_id: u64,
        planned: &[(u16, Vec<u8>)],
    ) -> anyhow::Result<()>;
}
