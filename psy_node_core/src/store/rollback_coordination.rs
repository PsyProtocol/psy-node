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

    /// Whether a participant may commit a new checkpoint in this phase.
    ///
    /// Only Idle.  Every phase of a rollback needs the old head to stay
    /// byte-for-byte stable -- before the archive because the plan is read from
    /// it, after because the archive is compared against it -- and the phases
    /// past DELETING are rewriting the very rows a commit would touch.  Aborting
    /// is no exception: the abort has not finished, and the node learns it may
    /// resume by observing Idle rather than by guessing from the abort.
    pub const fn permits_commit(self) -> bool {
        matches!(self, Self::Idle)
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

/// Bring this node's commit path into line with the phase the Coordinator has
/// published, and report the phase.
///
/// Called once per processor loop iteration, before the loop decides whether to
/// produce.  It is the whole of a participant's obligation outside its own
/// rollback work: freeze while a rollback is in flight, resume when it is over.
///
/// Freezing here rather than in the loop's own branches is the same argument the
/// commit window itself rests on -- one place that cannot be bypassed beats a
/// check at every site that decides to commit.  The loop may still forget to
/// call this, but that failure is visible (the node never freezes at all), where
/// a missed branch would be a node that freezes on most paths and commits on
/// one.
///
/// Thaws only on Idle.  A rollback that ended in an abort returns to Idle the
/// same way a successful one does, so the node needs no separate rule for it,
/// and a node that thawed on any earlier phase would resume committing while the
/// Coordinator was still restoring.
pub async fn follow_published_rollback_phase<Hash: Q256BitHash>(
    view: &dyn RollbackParticipantView<Hash>,
    coordinator_head: &CanonicalChainRef<Hash>,
    commit_window: &super::commit_window::CommitWindowClock,
) -> anyhow::Result<ObservedRollbackPhase> {
    let phase = view.observe_phase(coordinator_head).await?;
    apply_phase_to_commit_path(phase, commit_window);
    Ok(phase)
}

/// The one place that turns a phase into a freeze or a thaw.
///
/// Shared by the participant that reads the phase over a view and the
/// Coordinator that reads it out of its own head store: the source of the phase
/// differs, the obligation it creates does not.  Two copies of this would be two
/// chances for the roles to disagree about what a phase means.
pub fn apply_phase_to_commit_path(
    phase: ObservedRollbackPhase,
    commit_window: &super::commit_window::CommitWindowClock,
) {
    if phase.permits_commit() {
        commit_window.thaw_after_rollback();
    } else {
        commit_window.freeze_for_rollback();
    }
}

/// Whether a failed commit failed *because* a rollback is running.
///
/// A processor loop cannot check the phase and then commit atomically, so a
/// rollback that starts in between will meet a commit already under way.  Both
/// guards below refuse it, which is the outcome the guards exist for -- but a
/// refusal is not a fault, and treating it as one parks the node in Error and
/// stops the chain over a rollback that worked exactly as designed.  That is
/// what happened the first time a rollback ran against a live Coordinator: the
/// floor rejected the commit, the rollback completed correctly, and the
/// processor died anyway.
///
/// Two distinct guards answer here because they catch the race at different
/// depths: the commit window refuses to open at all, while the rollback floor
/// refuses a commit source built on a head that is no longer idle.  A node can
/// meet either depending on how far into the commit it had got.
pub fn is_refused_because_rollback(err: &anyhow::Error) -> bool {
    use super::commit_window::CommitWindowError;
    use super::coordinator_commit_source::CoordinatorCommitSourceError;

    if let Some(CommitWindowError::FrozenForRollback { .. }) =
        err.downcast_ref::<CommitWindowError>()
    {
        return true;
    }
    if let Some(CoordinatorCommitSourceError::RollbackFloorRequiresIdleHead) =
        err.downcast_ref::<CoordinatorCommitSourceError>()
    {
        return true;
    }
    false
}

/// The participant this node is.
pub fn participant_for(scope: psy_data::protocol::chain_context::AuthorityScope) -> RollbackParticipant {
    RollbackParticipant::new(scope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::commit_window::{CommitWindow, CommitWindowClock};
    use super::super::timestamp::CommitWriteTimestampUs;
    use std::sync::Arc;

    /// A Coordinator control row frozen at one phase, so the rule under test is
    /// the participant's reaction to it and nothing else.
    struct PublishedPhase(ObservedRollbackPhase);

    #[async_trait]
    impl<Hash: Q256BitHash> RollbackParticipantView<Hash> for PublishedPhase {
        async fn observe_phase(
            &self,
            _coordinator_head: &CanonicalChainRef<Hash>,
        ) -> anyhow::Result<ObservedRollbackPhase> {
            Ok(self.0)
        }
        async fn file_archive_receipt(&self, _receipt: &ArchiveReceipt) -> anyhow::Result<()> {
            unreachable!("following a phase files nothing")
        }
        async fn read_archive_receipts_for(
            &self,
            _target: u64,
            _head: u64,
            _expected: &[RollbackParticipant],
        ) -> anyhow::Result<Vec<ArchiveReceipt>> {
            unreachable!("following a phase reads no receipts")
        }
        async fn file_freeze_receipt(&self, _receipt: &FreezeReceipt) -> anyhow::Result<()> {
            unreachable!("following a phase files nothing")
        }
        async fn read_freeze_receipts_for(
            &self,
            _head: u64,
            _expected: &[RollbackParticipant],
        ) -> anyhow::Result<Vec<FreezeReceipt>> {
            unreachable!("following a phase reads no receipts")
        }
        async fn file_verify_receipt(&self, _receipt: &VerifyReceipt) -> anyhow::Result<()> {
            unreachable!("following a phase files nothing")
        }
        async fn read_verify_receipts_for(
            &self,
            _target: u64,
            _expected: &[RollbackParticipant],
        ) -> anyhow::Result<Vec<VerifyReceipt>> {
            unreachable!("following a phase reads no receipts")
        }
    }

    fn head() -> CanonicalChainRef<parth_core::PHash> {
        use parth_core::PHash;
        use psy_core::constants::chain_id::PsyChainNetworkType;
        use psy_data::protocol::canonical_chain::{
            ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId,
        };
        CanonicalChainRef::new(
            NetworkId::from(PsyChainNetworkType::PsyMainnet),
            ChainEpoch::new(1),
            CheckpointRef::new(
                CheckpointId::new(100),
                CheckpointHash::from_last_chain_hash(PHash::from_values(7, 8, 9, 10)),
            ),
        )
    }

    async fn phase_leaves_clock(phase: ObservedRollbackPhase) -> bool {
        let clock = Arc::new(CommitWindowClock::new());
        follow_published_rollback_phase(&PublishedPhase(phase), &head(), &clock)
            .await
            .expect("the fake view always answers");
        clock.is_frozen()
    }

    #[tokio::test]
    async fn every_phase_of_a_rollback_freezes_the_commit_path() {
        // Not just the freeze phase.  The plan is read from the old head before
        // the archive and compared against it after, and past DELETING the rows
        // a commit would write are the ones being rewritten.
        for phase in [
            ObservedRollbackPhase::Requested,
            ObservedRollbackPhase::Freeze { head: 100 },
            ObservedRollbackPhase::Archive { target: 90, head: 100 },
            ObservedRollbackPhase::Delete { target: 90, head: 100 },
            ObservedRollbackPhase::Restore { target: 90 },
            ObservedRollbackPhase::Verify { target: 90 },
            ObservedRollbackPhase::Aborting,
        ] {
            assert!(
                phase_leaves_clock(phase).await,
                "{phase:?} must not leave this node committing"
            );
        }
    }

    #[tokio::test]
    async fn only_idle_lets_the_chain_run() {
        assert!(!phase_leaves_clock(ObservedRollbackPhase::Idle).await);
    }

    #[tokio::test]
    async fn an_abort_thaws_by_returning_to_idle_like_any_other_ending() {
        // The node needs no separate rule for abort: it resumes when the
        // Coordinator publishes Idle, whatever put it there.
        let clock = Arc::new(CommitWindowClock::new());
        follow_published_rollback_phase(&PublishedPhase(ObservedRollbackPhase::Aborting), &head(), &clock)
            .await
            .expect("the fake view always answers");
        assert!(clock.is_frozen());
        follow_published_rollback_phase(&PublishedPhase(ObservedRollbackPhase::Idle), &head(), &clock)
            .await
            .expect("the fake view always answers");
        assert!(!clock.is_frozen());
        let stamp = CommitWriteTimestampUs::try_from_i128(1_700_000_000_000_000).expect("in range");
        assert!(
            clock.open(CommitWindow::new(101, stamp)).is_ok(),
            "an aborted rollback must give the chain back"
        );
    }

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

    #[test]
    fn a_commit_refused_by_a_rollback_is_not_a_fault() {
        use super::super::commit_window::CommitWindowError;
        use super::super::coordinator_commit_source::CoordinatorCommitSourceError;

        // Both depths, because a commit meets one or the other depending on how
        // far it had got when the rollback started.
        assert!(is_refused_because_rollback(&anyhow::Error::new(
            CommitWindowError::FrozenForRollback { requested: 92 }
        )));
        assert!(is_refused_because_rollback(&anyhow::Error::new(
            CoordinatorCommitSourceError::RollbackFloorRequiresIdleHead
        )));
    }

    #[test]
    fn it_survives_the_context_a_commit_path_adds() {
        use anyhow::Context;
        use super::super::commit_window::CommitWindowError;

        // The processor sees this error through several layers of context, and
        // a classification that only worked on the bare error would quietly
        // stop working the first time someone annotated the call.
        let wrapped = Err::<(), _>(CommitWindowError::FrozenForRollback { requested: 92 })
            .context("recording checkpoint 92")
            .context("process_block")
            .unwrap_err();
        assert!(is_refused_because_rollback(&wrapped));
    }

    #[test]
    fn an_ordinary_failure_still_parks_the_node() {
        use super::super::commit_window::CommitWindowError;

        // A window left open by a lost guard is a real defect and must not be
        // waved through as backpressure.
        assert!(!is_refused_because_rollback(&anyhow::Error::new(
            CommitWindowError::AlreadyOpen { open: 91, requested: 92 }
        )));
        assert!(!is_refused_because_rollback(&anyhow::anyhow!(
            "the worker returned no proof"
        )));
    }
}
