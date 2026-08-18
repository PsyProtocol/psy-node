//! What a participant may do during a rollback, and what only the Coordinator may.
//!
//! §6.2 draws the line: every barrier is an LWT advance on the Coordinator's
//! control row, participants observe that row, and **a participant must not
//! advance a phase itself**.  Left as prose that is a rule people follow until
//! someone is in a hurry; here it is the shape of the traits.
//!
//! A participant gets [`RollbackParticipantView`]: it can read the phase and
//! file its own receipt.  There is no method on it that changes a phase.  The
//! Coordinator gets the head store as before, which is where phases move.
//!
//! ## Why receipts are durable rather than in-memory
//!
//! The barrier aggregates evidence across processes and across restarts.  A
//! Coordinator that crashed between a Realm's receipt and the barrier must find
//! that receipt when it comes back, or it would either wait forever for a
//! participant that already finished, or -- worse -- re-run an archive whose
//! rows are already in the archive table under a different plan.

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::CanonicalChainRef;

use super::canonical_head::CanonicalHeadReadState;
use super::rollback_control::RollbackControlState;
use super::rollback_participants::{
    ArchiveReceipt, FreezeReceipt, RollbackParticipant, VerifyReceipt,
};

/// Where a rollback stands, as a participant sees it.
///
/// Deliberately not the full control state: a participant needs to know what to
/// do next, not to reason about transitions it may not perform.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedRollbackPhase {
    /// No rollback in progress.
    Idle,
    /// Requested but not yet archiving.  A participant freezes here.
    Requested,
    /// Archive your share of the range and file a receipt.
    Archive { target: u64, head: u64 },
    /// Stop producing new side effects, drain what is in flight, and report the
    /// head once it stops changing.
    Freeze { head: u64 },
    /// Every participant archived; the Coordinator has crossed the barrier.
    /// Deleting is now permitted -- and only now.
    Delete { target: u64, head: u64 },
    /// Restore the target state.
    Restore { target: u64 },
    /// Verify, then wait to be published.
    Verify { target: u64 },
    /// An abort is running; stop and expect to return to Idle.
    Aborting,
}

impl ObservedRollbackPhase {
    /// Whether a participant may destroy anything in this phase.
    ///
    /// One place answers this so no caller has to re-derive it from a phase
    /// name, and every non-destructive phase answers false rather than
    /// defaulting to true for anything unrecognised.
    pub const fn permits_destruction(self) -> bool {
        matches!(self, Self::Delete { .. })
    }

    pub fn from_control<Hash: Q256BitHash>(state: &RollbackControlState<Hash>) -> Self {
        match state {
            RollbackControlState::Idle => Self::Idle,
            RollbackControlState::Requested(_) => Self::Requested,
            RollbackControlState::Frozen(request) => Self::Freeze {
                head: request.requested_head().checkpoint_id().get(),
            },
            RollbackControlState::Archiving(request) => Self::Archive {
                target: request.target().checkpoint_id().get(),
                head: request.requested_head().checkpoint_id().get(),
            },
            // The barrier is crossed but deletion has not begun.  A participant
            // that started deleting here would be ahead of the Coordinator's own
            // durable phase, so it reads as Delete only once DELETING is
            // published -- the barrier state itself still permits nothing.
            RollbackControlState::ArchiveBarrierReady(request) => Self::Archive {
                target: request.target().checkpoint_id().get(),
                head: request.requested_head().checkpoint_id().get(),
            },
            RollbackControlState::Deleting(request) => Self::Delete {
                target: request.target().checkpoint_id().get(),
                head: request.requested_head().checkpoint_id().get(),
            },
            RollbackControlState::Restoring(request) => Self::Restore {
                target: request.target().checkpoint_id().get(),
            },
            RollbackControlState::Verifying(request)
            | RollbackControlState::AllRealmsReady(request) => Self::Verify {
                target: request.target().checkpoint_id().get(),
            },
            RollbackControlState::Aborting(_) => Self::Aborting,
        }
    }
}

/// A participant's view of a rollback.
///
/// Read the phase, file a receipt.  There is deliberately no way from here to
/// move a phase: §6.2 puts every barrier on the Coordinator, and a participant
/// that could advance one could cross the point of no return for everybody.
#[async_trait]
pub trait RollbackParticipantView<Hash: Q256BitHash>: Send + Sync {
    /// What the Coordinator's control row currently says.
    async fn observe_phase(
        &self,
        coordinator_head: &CanonicalChainRef<Hash>,
    ) -> anyhow::Result<ObservedRollbackPhase>;

    /// Record that this participant archived the range.
    ///
    /// Durable, because the barrier aggregates across restarts: a Coordinator
    /// that crashed after this must find the receipt rather than wait for a
    /// participant that already finished.
    async fn file_archive_receipt(&self, receipt: &ArchiveReceipt) -> anyhow::Result<()>;

    /// Receipts for one range, resolved against the participants the caller
    /// expects.
    ///
    /// Takes the expected set rather than returning whatever the table holds,
    /// so a stored row can only ever fill a slot that already exists.  A reader
    /// that decoded identities out of storage could produce a participant the
    /// set never contained, and refusing evidence from outside the set is
    /// precisely what the barrier is for.
    async fn read_archive_receipts_for(
        &self,
        target: u64,
        head: u64,
        expected: &[RollbackParticipant],
    ) -> anyhow::Result<Vec<ArchiveReceipt>>;

    /// Record that this participant froze the old head and drained.
    async fn file_freeze_receipt(&self, receipt: &FreezeReceipt) -> anyhow::Result<()>;

    /// Freeze receipts for one head, resolved against the expected set.
    async fn read_freeze_receipts_for(
        &self,
        head: u64,
        expected: &[RollbackParticipant],
    ) -> anyhow::Result<Vec<FreezeReceipt>>;

    /// Record that this participant verified the restored target.
    ///
    /// Filed after RESTORING and read at the publish barrier.  Durable for the
    /// same reason the archive receipt is: the barrier aggregates across
    /// processes and restarts.
    async fn file_verify_receipt(&self, receipt: &VerifyReceipt) -> anyhow::Result<()>;

    /// Verify receipts for one target, resolved against the expected set.
    async fn read_verify_receipts_for(
        &self,
        target: u64,
        expected: &[RollbackParticipant],
    ) -> anyhow::Result<Vec<VerifyReceipt>>;
}

/// Read a phase from a head-read result.
///
/// An uninitialised head is Idle rather than an error: a Realm that starts
/// before the Coordinator has published anything has no rollback to join.
pub fn phase_from_head_state<Hash: Q256BitHash>(
    state: &CanonicalHeadReadState<Hash>,
) -> ObservedRollbackPhase {
    match state {
        CanonicalHeadReadState::Current(head) => {
            ObservedRollbackPhase::from_control(head.rollback_control())
        }
        CanonicalHeadReadState::Uninitialized => ObservedRollbackPhase::Idle,
    }
}

/// The participant this node is.
pub fn participant_for(scope: psy_data::protocol::chain_context::AuthorityScope) -> RollbackParticipant {
    RollbackParticipant::new(scope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_deleting_phase_permits_destruction() {
        // Every other phase answers false explicitly rather than by omission,
        // so a phase added later does not silently become destructive.
        assert!(ObservedRollbackPhase::Delete { target: 1, head: 2 }.permits_destruction());
        for phase in [
            ObservedRollbackPhase::Idle,
            ObservedRollbackPhase::Requested,
            ObservedRollbackPhase::Archive { target: 1, head: 2 },
            ObservedRollbackPhase::Restore { target: 1 },
            ObservedRollbackPhase::Verify { target: 1 },
            ObservedRollbackPhase::Aborting,
        ] {
            assert!(!phase.permits_destruction(), "{phase:?} must not permit destruction");
        }
    }
}
