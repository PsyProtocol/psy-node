//! Undoing a Realm's *own* committed state after a rollback it did not drive.
//!
//! A Realm has two kinds of state above a rollback target and they are undone
//! two different ways (design-r1 §6.3).  What it copied from the Coordinator is
//! undone by resetting its sync markers and fetching again -- that is
//! `reset_for_rollback_to`, and it is all an idle Realm ever needs.  What it
//! *wrote itself*, because it had transactions, is named by its own manifest and
//! has to be archived and deleted like any other discarded suffix.
//!
//! Only the first half existed.  A Realm that had committed anything in the
//! discarded range kept it, and because the Coordinator no longer acknowledges
//! that commit the two disagree about the Realm's root forever: the Coordinator
//! reports the Realm last changed at some earlier checkpoint while the Realm
//! reports the discarded one, and every sync fails with a root mismatch.  An
//! idle Realm never shows this, which is why it survived so long.
//!
//! ## Why this may destroy without waiting for a barrier
//!
//! Every other destructive step in this design waits for
//! `GLOBAL_ARCHIVE_BARRIER`, because deleting before every participant has
//! copied its share is unrecoverable.  This one runs *after* the rollback has
//! finished and the new epoch has been published -- the point of no return is
//! already behind it, and the chain has already told the world where it is.
//! Waiting for a barrier that was crossed before this code ran would mean
//! waiting forever.
//!
//! It still archives before deleting.  The barrier is about coordinating
//! participants; the archive is about being able to answer what was discarded,
//! and that obligation does not expire.

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::CanonicalChainRef;

use super::realm_commit_recording::RealmCommitRecording;

/// What the recovery did.  Zero rows is the ordinary outcome -- a Realm with no
/// transactions in the discarded range has nothing of its own to undo.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RealmSelfRollbackReport {
    pub own_head: u64,
    pub target: u64,
    pub planned_rows: usize,
    pub archived_rows: usize,
    pub deleted_rows: usize,
}

impl RealmSelfRollbackReport {
    /// Whether anything was actually undone.
    pub const fn changed_anything(&self) -> bool {
        self.deleted_rows > 0
    }
}

#[async_trait]
pub trait RealmSelfRollback<Hash: Q256BitHash>: Send + Sync {
    /// Archive and delete everything this Realm committed above `target`.
    ///
    /// The Realm's own head is discovered from its own manifest rather than
    /// taken from the Coordinator: right after a rollback the Coordinator's
    /// height is the target itself, and a Realm that planned against that would
    /// compute an empty range and silently keep the very rows this exists to
    /// remove.
    ///
    /// `search_head` bounds that discovery.  It is passed rather than assumed
    /// infinite because the manifest is bucketed and an unbounded scan spans
    /// more than one bucket, and because the caller is what knows how far this
    /// Realm could have got: no Realm commits above the highest Coordinator
    /// checkpoint it ever synced.  Its height is the only part read -- the
    /// network comes from the same reference, the hash is not consulted.
    async fn recover_own_state_to(
        &self,
        recording: &RealmCommitRecording<Hash>,
        realm_id: u32,
        realm_sub_id: u16,
        search_head: &CanonicalChainRef<Hash>,
        target: u64,
    ) -> anyhow::Result<RealmSelfRollbackReport>;
}

/// Taking part in a rollback while it is happening, as opposed to recovering
/// from one afterwards.
///
/// The two are not alternatives.  Recovery has to exist because a Realm can be
/// down for the whole rollback, and participation has to exist because without
/// it the archive barrier means nothing for Realms: the Coordinator would cross
/// the point of no return while a Realm had copied none of its share.  A Realm
/// that is up does this; one that was not does the other when it returns.
#[async_trait]
pub trait RealmRollbackParticipation<Hash: Q256BitHash>: Send + Sync {
    /// Run this Realm's share of the rollback the Coordinator has published,
    /// filing the receipts its barriers wait for.
    async fn take_part_in_rollback(
        &self,
        recording: &RealmCommitRecording<Hash>,
        realm_id: u32,
        realm_sub_id: u16,
        head: &CanonicalChainRef<Hash>,
        target: u64,
    ) -> anyhow::Result<RealmSelfRollbackReport>;

    /// Confirm this Realm holds nothing above `target` and file the verify
    /// receipt PUBLISH_ALL waits for.
    ///
    /// Earned by checking rather than by remembering.  A Realm that took part,
    /// one that was restarted half way through and lost the fact, and one that
    /// never had anything above the target all owe the same receipt, and only
    /// the first would be able to file it from memory.  Checking costs one
    /// manifest read and is true for all three.
    ///
    /// Anything still found above the target is undone here rather than
    /// reported: the receipt says the Realm reached the target, and filing it
    /// while rows remained would be the participant lying to the barrier that
    /// exists to catch exactly that.
    async fn confirm_target_reached(
        &self,
        recording: &RealmCommitRecording<Hash>,
        realm_id: u32,
        realm_sub_id: u16,
        search_head: &CanonicalChainRef<Hash>,
        target: u64,
    ) -> anyhow::Result<()>;
}
