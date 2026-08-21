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
    Requested { target: u64 },
    /// Archive your share of the range and file a receipt.
    Archive { target: u64, head: u64 },
    /// Stop producing new side effects, drain what is in flight, and report the
    /// head once it stops changing.
    ///
    /// Carries the target because this is where a participant joins: it files a
    /// freeze receipt and then runs its own share, and the archive barrier can
    /// only wait for a receipt a running participant files.  An earlier version
    /// left the target out on the reasoning that nothing acts this early; that
    /// was wrong, and it was what made Realms unable to take part at all.
    Freeze { head: u64, target: u64 },
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

    /// Whether a participant that joined this rollback may now do the work of
    /// `required`.
    ///
    /// At-or-past rather than exactly-equal.  The Coordinator does not wait for
    /// Realms -- it guarantees its own consistency and leaves each Realm to
    /// reach the same target at its own pace -- so by the time a Realm looks,
    /// the phase it was waiting for has often gone by.  Insisting on the exact
    /// phase made a Realm able to take part only in a rollback it happened to
    /// be in step with.
    ///
    /// Idle counts as past everything, and that is the case this exists for: a
    /// rollback is never abandoned once requested, so a participant that
    /// started sees Idle only after the rollback it joined has finished.
    /// Everything it still owes is in its own keyspace, and the Coordinator
    /// having finished can only ever have authorised more.
    pub const fn permits_work_of(self, required: u8) -> bool {
        match self.reached_ordinal() {
            Some(reached) => reached >= required,
            None => matches!(self, Self::Idle),
        }
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

    /// How far the rollback has got, on the same scale the phase machine uses.
    ///
    /// `None` for Idle, which on this side means "not in a rollback" and cannot
    /// be compared with the others -- a participant that read it as "before
    /// everything" would conclude it must wait for a rollback that has already
    /// finished.
    pub const fn reached_ordinal(self) -> Option<u8> {
        use super::rollback_control::{
            PHASE_ORDINAL_ARCHIVE_BARRIER_READY, PHASE_ORDINAL_ARCHIVING, PHASE_ORDINAL_DELETING,
            PHASE_ORDINAL_FROZEN, PHASE_ORDINAL_REQUESTED, PHASE_ORDINAL_RESTORING,
            PHASE_ORDINAL_VERIFYING,
        };
        match self {
            Self::Requested { .. } => Some(PHASE_ORDINAL_REQUESTED),
            Self::Freeze { .. } => Some(PHASE_ORDINAL_FROZEN),
            // ArchiveBarrierReady is reported as Archive, so this is the floor
            // of the two: a participant may archive, and must not assume the
            // barrier is sealed.
            Self::Archive { .. } => Some(PHASE_ORDINAL_ARCHIVING),
            Self::Delete { .. } => Some(PHASE_ORDINAL_DELETING),
            Self::Restore { .. } => Some(PHASE_ORDINAL_RESTORING),
            Self::Verify { .. } => Some(PHASE_ORDINAL_VERIFYING),
            Self::Idle | Self::Aborting => None,
        }
    }

    /// The height this rollback is heading for, when the phase names one.
    ///
    /// Every phase of a live rollback does.  `Aborting` deliberately does not:
    /// it carries a request like the others, but a participant that acted on
    /// the target of a rollback being abandoned would undo state the chain
    /// never discarded.
    pub const fn target(self) -> Option<u64> {
        match self {
            Self::Requested { target }
            | Self::Freeze { target, .. }
            | Self::Archive { target, .. }
            | Self::Delete { target, .. }
            | Self::Restore { target }
            | Self::Verify { target } => Some(target),
            Self::Idle | Self::Aborting => None,
        }
    }

    pub fn from_control<Hash: Q256BitHash>(state: &RollbackControlState<Hash>) -> Self {
        match state {
            RollbackControlState::Idle => Self::Idle,
            RollbackControlState::Requested(request) => Self::Requested {
                target: request.target().checkpoint_id().get(),
            },
            RollbackControlState::Frozen(request) => Self::Freeze {
                head: request.requested_head().checkpoint_id().get(),
                target: request.target().checkpoint_id().get(),
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

    /// The head the Coordinator currently publishes, or `None` when it has
    /// never published one.
    ///
    /// Separate from `observe_phase` because it answers a different question: a
    /// participant that missed the whole rollback -- because it was down for it
    /// -- sees Idle and learns nothing, while the published head still says
    /// where the chain is.  That is the only evidence available to a node that
    /// was not watching.
    async fn observe_published_head(
        &self,
        coordinator_head: &CanonicalChainRef<Hash>,
    ) -> anyhow::Result<Option<CanonicalChainRef<Hash>>>;

    /// The target of every rollback this chain performed after `epoch`,
    /// newest first, as `(chain_epoch, target)`.
    ///
    /// A participant that missed a rollback learns *that* one happened from the
    /// epoch, but the epoch does not say where the discarded branch began --
    /// and by the time the participant looks, the Coordinator has usually
    /// produced past it again, so the current head does not say either.  The
    /// lowest target across the rollbacks it missed is the height above which
    /// everything it still holds belongs to a branch that no longer exists.
    async fn read_rollback_targets_after(
        &self,
        epoch: u64,
    ) -> anyhow::Result<Vec<(u64, u64)>>;

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

/// The Coordinator's record of a Realm's root is neither the value the Realm
/// started from nor the one it is proposing.
///
/// A rollback is the expected cause: it moves the Realm root back to what it was
/// at the target, which is neither end of the transition an in-flight Realm
/// update is proving.  The Realm cannot see this coming -- it is blocked inside
/// a wait when the rollback lands, so the phase check at the top of its loop has
/// already been passed.
///
/// Typed so it can be recognised.  It was an `anyhow::bail!` with "CRITICAL" and
/// "Aborting" in the text, and the Realm holding real transaction state died on
/// it the first time a rollback ran under load -- the fourth guard in this
/// design to work correctly and stop a node anyway.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmRootMovedUnderUs;

impl std::fmt::Display for RealmRootMovedUnderUs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the Coordinator's record of this Realm's root is neither the value this update \
             started from nor the one it proposes; a rollback has moved it",
        )
    }
}

impl std::error::Error for RealmRootMovedUnderUs {}

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
/// Three distinct guards answer here because they catch the race at different
/// depths: the commit window refuses to open at all, the rollback floor refuses
/// a commit source built on a head that is no longer idle, and the head itself
/// refuses a normal advance while rollback control is active.  Which one a node
/// meets depends on how far into the commit it had got, so all three count --
/// the third was found only when a second rollback landed on a Coordinator that
/// had just restarted from the first.
pub fn is_refused_because_rollback(err: &anyhow::Error) -> bool {
    use super::canonical_head::CanonicalHeadModelError;
    use super::commit_window::CommitWindowError;
    use super::coordinator_commit_source::CoordinatorCommitSourceError;

    if let Some(CanonicalHeadModelError::NormalAdvanceWhileRollbackActive) =
        err.downcast_ref::<CanonicalHeadModelError>()
    {
        return true;
    }
    // The Realm's counterpart: it was blocked in a wait when the rollback moved
    // the root out from under the update it was proving.  Abandoning that block
    // is right; dying is not, because the next iteration re-derives from the
    // state the rollback left.
    if err.downcast_ref::<RealmRootMovedUnderUs>().is_some() {
        return true;
    }

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
    #[test]
    fn a_refusal_is_still_a_refusal_under_context() {
        // The Realm abandons a block from inside a proof wait and explains why
        // with `.context`. The classifier downcasts rather than reading the
        // message, and the Realm's loop parks the processor in Error for
        // anything it does not recognise -- so a refusal that stopped being
        // recognised once wrapped would abandon the block and then stop the
        // Realm for having abandoned it.
        use super::super::canonical_head::CanonicalHeadModelError;
        use anyhow::Context;
        let bare = anyhow::Error::new(CanonicalHeadModelError::NormalAdvanceWhileRollbackActive);
        assert!(super::is_refused_because_rollback(&bare));
        let explained = anyhow::Error::new(
            CanonicalHeadModelError::NormalAdvanceWhileRollbackActive,
        )
        .context("a rollback was published while this block waited for proofs");
        assert!(
            super::is_refused_because_rollback(&explained),
            "context must not hide the type the classifier looks for"
        );
    }

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
        async fn observe_published_head(
            &self,
            _coordinator_head: &CanonicalChainRef<Hash>,
        ) -> anyhow::Result<Option<CanonicalChainRef<Hash>>> {
            unreachable!("following a phase does not read the head separately")
        }
        async fn read_rollback_targets_after(
            &self,
            _epoch: u64,
        ) -> anyhow::Result<Vec<(u64, u64)>> {
            unreachable!("following a phase does not read the history")
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
            ObservedRollbackPhase::Requested { target: 90 },
            ObservedRollbackPhase::Freeze { head: 100, target: 90 },
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
            ObservedRollbackPhase::Requested { target: 90 },
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
        assert!(is_refused_because_rollback(&anyhow::Error::new(
            super::super::canonical_head::CanonicalHeadModelError::NormalAdvanceWhileRollbackActive
        )));
        // The Realm's, which is the only one a node can meet while blocked
        // inside a wait rather than while committing.
        assert!(is_refused_because_rollback(&anyhow::Error::new(
            RealmRootMovedUnderUs
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

    #[test]
    fn only_the_phases_a_participant_acts_on_name_a_target() {
        // Requested and Freeze deliberately do not: the participant set is
        // fixed and the head is settling, but there is nothing yet to undo to.
        assert_eq!(
            ObservedRollbackPhase::Archive { target: 90, head: 100 }.target(),
            Some(90)
        );
        assert_eq!(
            ObservedRollbackPhase::Delete { target: 90, head: 100 }.target(),
            Some(90)
        );
        assert_eq!(ObservedRollbackPhase::Restore { target: 90 }.target(), Some(90));
        assert_eq!(ObservedRollbackPhase::Verify { target: 90 }.target(), Some(90));
        assert_eq!(
            ObservedRollbackPhase::Requested { target: 90 }.target(),
            Some(90)
        );
        assert_eq!(
            ObservedRollbackPhase::Freeze { head: 100, target: 90 }.target(),
            Some(90)
        );
        for phase in [ObservedRollbackPhase::Idle, ObservedRollbackPhase::Aborting] {
            assert_eq!(phase.target(), None, "{phase:?} must not name a target");
        }
    }

    #[test]
    fn a_participant_learns_the_target_at_the_freeze_where_it_joins() {
        // The freeze is the only moment a Realm can join: it files a receipt
        // and runs its own share, and the archive barrier waits for that.  An
        // earlier version left the target out of this phase, which is exactly
        // what made Realms unable to take part.
        assert_eq!(
            ObservedRollbackPhase::Freeze { head: 100, target: 90 }.target(),
            Some(90)
        );
    }

    #[test]
    fn an_aborting_rollback_names_no_target_to_act_on() {
        // It carries a request like any other phase, but acting on it would
        // undo state the chain never discarded.
        assert_eq!(ObservedRollbackPhase::Aborting.target(), None);
    }

    #[test]
    fn a_participant_may_act_on_a_phase_the_rollback_has_already_passed() {
        use super::super::rollback_control::{PHASE_ORDINAL_ARCHIVING, PHASE_ORDINAL_DELETING};

        // The Coordinator does not wait for Realms, so by the time one looks the
        // phase it needed has usually gone by.  Requiring the exact phase made a
        // Realm able to take part only in a rollback it happened to be in step
        // with.
        assert!(
            ObservedRollbackPhase::Delete { target: 90, head: 100 }
                .permits_work_of(PHASE_ORDINAL_ARCHIVING)
        );
        assert!(
            ObservedRollbackPhase::Verify { target: 90 }.permits_work_of(PHASE_ORDINAL_DELETING)
        );
    }

    #[test]
    fn a_participant_may_not_delete_before_the_rollback_reaches_deleting() {
        use super::super::rollback_control::PHASE_ORDINAL_DELETING;

        // The half of the rule that still bites: deleting before the archive
        // barrier is the one mistake nothing downstream can repair.
        for phase in [
            ObservedRollbackPhase::Requested { target: 90 },
            ObservedRollbackPhase::Freeze { head: 100, target: 90 },
            ObservedRollbackPhase::Archive { target: 90, head: 100 },
        ] {
            assert!(
                !phase.permits_work_of(PHASE_ORDINAL_DELETING),
                "{phase:?} must not authorise a delete"
            );
        }
    }

    #[test]
    fn idle_counts_as_past_everything_for_a_participant_that_joined() {
        use super::super::rollback_control::PHASE_ORDINAL_DELETING;

        // A rollback is never abandoned once requested, so a Realm that started
        // sees Idle only after the one it joined finished.  What it still owes
        // is in its own keyspace, and the Coordinator finishing can only have
        // authorised more of it.  Reading Idle as "before everything" would
        // leave the Realm waiting for a rollback that already happened.
        assert!(ObservedRollbackPhase::Idle.permits_work_of(PHASE_ORDINAL_DELETING));
        assert_eq!(ObservedRollbackPhase::Idle.reached_ordinal(), None);
    }
}
