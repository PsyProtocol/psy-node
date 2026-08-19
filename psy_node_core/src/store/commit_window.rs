//! The write timestamp one commit's rows share, and the window that carries it.
//!
//! Scylla stamps every cell with a write timestamp and resolves conflicts by
//! taking the larger one; a tombstone only hides data whose timestamp is below
//! its own.  Left alone the server fills that field from the writing node's wall
//! clock, which is neither monotonic across nodes nor comparable with a delete
//! fence we deliberately place in the future.
//!
//! Rollback needs both properties, so design-r1 §2.1 takes the field over: the
//! allocator issues `max(high_water + 1, clock_sample)`, monotonic like a version
//! counter and anchored to microseconds like a clock.  The anchoring is not
//! decoration -- a counter starting at 1 would sit below every row already in the
//! database, and each new write would be invisible while still reporting success.
//!
//! ## Why this is ambient rather than a parameter
//!
//! One commit writes about twenty tables through as many trait methods, and the
//! timestamp is decided long before any of them.  Threading it through every
//! signature would touch every caller of those methods, including the Realm and
//! query paths that hold no timestamp at all and could only pass `None` -- which
//! puts the mixing hazard back, and in the one place the compiler stops helping.
//!
//! So the window is ambient, and the driver's session timestamp generator reads
//! it on every statement (see `rollback::commit_window_generator`).  That is a
//! chokepoint below prepared statements, unprepared statements and batches
//! alike, so no adapter can write around it and there is no per-adapter stamping
//! to forget.
//!
//! What the window deliberately does *not* do is refuse writes that happen
//! outside it.  The generator cannot decline -- it returns an `i64` -- and the
//! same session carries the edge and query paths, which never write a table a
//! rollback deletes from.  The guard against a write escaping its commit is
//! therefore [`require_checkpoint`](CommitWindowClock::require_checkpoint) in
//! process, and `WRITETIME()` on the stored rows after the fact: every row of a
//! checkpoint must carry that checkpoint's timestamp exactly.
//!
//! ## The failure this prevents
//!
//! Per key, either every write carries an allocated timestamp or none does.
//! Mixing loses data rather than merely leaving some behind: once a fence has
//! pushed a key's timestamp ahead of the wall clock, a later write taking the
//! server default lands *below* it and is shadowed.  The write succeeds, returns
//! no error, and the row simply cannot be read.

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

use super::timestamp::CommitWriteTimestampUs;

/// The timestamp every row of one commit shares, and the checkpoint it belongs
/// to.
///
/// One timestamp per commit rather than per row is what makes a commit atomic
/// under last-write-wins: a reader cannot see half of it win and half of it lose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitWindow {
    checkpoint_id: u64,
    timestamp: CommitWriteTimestampUs,
}

impl CommitWindow {
    pub const fn new(checkpoint_id: u64, timestamp: CommitWriteTimestampUs) -> Self {
        Self {
            checkpoint_id,
            timestamp,
        }
    }

    pub const fn checkpoint_id(&self) -> u64 {
        self.checkpoint_id
    }

    pub const fn timestamp(&self) -> CommitWriteTimestampUs {
        self.timestamp
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitWindowError {
    /// The commit path asked for its timestamp with no window open.
    NoActiveWindow { checkpoint_id: u64 },
    /// The open window belongs to a different checkpoint than the one being
    /// committed.
    ///
    /// Either two commits are running at once or one outlived its guard; both
    /// would stamp rows with a timestamp that is not theirs.
    CheckpointMismatch { window: u64, commit: u64 },
    /// A second window was opened while one was still open.  Commits are
    /// serialised by construction, so this means the caller lost track of one.
    AlreadyOpen { open: u64, requested: u64 },
    /// A commit tried to start while this node is frozen for a rollback.
    ///
    /// Not a fault: the node has been told to stop producing so the head it is
    /// about to hand over stops moving.  The caller should back off and try
    /// again once the rollback finishes.
    FrozenForRollback { requested: u64 },
}

impl fmt::Display for CommitWindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoActiveWindow { checkpoint_id } => write!(
                f,
                "checkpoint {checkpoint_id} asked for its write timestamp with no commit window \
                 open, so its rows would carry a wall clock timestamp instead"
            ),
            Self::CheckpointMismatch { window, commit } => write!(
                f,
                "the open commit window belongs to checkpoint {window}, not to checkpoint {commit}"
            ),
            Self::AlreadyOpen { open, requested } => write!(
                f,
                "a commit window for checkpoint {open} is still open; checkpoint {requested} \
                 cannot open another"
            ),
            Self::FrozenForRollback { requested } => write!(
                f,
                "checkpoint {requested} cannot commit: this node is frozen for a rollback and \
                 its head must stay byte-for-byte stable until the archive is taken"
            ),
        }
    }
}

impl Error for CommitWindowError {}

/// The commit window the store is currently writing under, if any.
///
/// Lives on the store because that is what every adapter already reaches.  It is
/// only ever open inside one `commit_state` call, so the lock is uncontended;
/// it exists to make the state observable from the adapters, not to arbitrate
/// between writers.
#[derive(Debug, Default)]
pub struct CommitWindowClock {
    state: Mutex<ClockState>,
}

/// The window and the freeze flag share one lock deliberately.  Held apart, a
/// commit could read "not frozen", be preempted, and insert its window after the
/// freeze took effect -- writing a row into the range a rollback is about to
/// treat as final.
#[derive(Debug, Default)]
struct ClockState {
    open: Option<CommitWindow>,
    frozen: bool,
}

impl CommitWindowClock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open the window for one commit.
    ///
    /// The returned guard closes it on drop, including on the early return of a
    /// failed commit: a window left open would let the next commit's rows borrow
    /// this one's timestamp.
    /// Takes `&Arc<Self>` so the guard can own its handle.  A guard borrowing the
    /// clock would borrow whatever holds it for the length of the commit, and the
    /// commit needs `&mut self` on the processor after opening it.
    pub fn open(
        self: &Arc<Self>,
        window: CommitWindow,
    ) -> Result<CommitWindowGuard, CommitWindowError> {
        let mut state = self.state.lock().expect("commit window mutex poisoned");
        if state.frozen {
            return Err(CommitWindowError::FrozenForRollback {
                requested: window.checkpoint_id(),
            });
        }
        if let Some(existing) = state.open {
            return Err(CommitWindowError::AlreadyOpen {
                open: existing.checkpoint_id(),
                requested: window.checkpoint_id(),
            });
        }
        state.open = Some(window);
        drop(state);
        Ok(CommitWindowGuard {
            clock: Arc::clone(self),
        })
    }

    /// The timestamp this checkpoint's rows must carry, proving the open window
    /// is in fact its own.
    ///
    /// The comparison costs nothing and it is the only in-process guard against
    /// a second commit borrowing this window: the generator that stamps the rows
    /// sees statements, not checkpoints, so it cannot notice the difference.
    /// After the fact `WRITETIME()` on the stored rows checks the same property
    /// against the data rather than the code.
    pub fn require_checkpoint(
        &self,
        checkpoint_id: u64,
    ) -> Result<CommitWriteTimestampUs, CommitWindowError> {
        let window = self
            .peek()
            .ok_or(CommitWindowError::NoActiveWindow { checkpoint_id })?;
        if window.checkpoint_id() != checkpoint_id {
            return Err(CommitWindowError::CheckpointMismatch {
                window: window.checkpoint_id(),
                commit: checkpoint_id,
            });
        }
        Ok(window.timestamp())
    }

    /// The open window, if any.  This is what the session's timestamp generator
    /// reads on every statement.
    pub fn peek(&self) -> Option<CommitWindow> {
        self.state.lock().expect("commit window mutex poisoned").open
    }

    /// Stop admitting commits, for a rollback this node takes part in.
    ///
    /// This is the freeze `FREEZE_ALL` waits on, and it is placed here rather
    /// than in the processor loops for the reason the ambient window itself
    /// exists: both roles open their window through this one object, so freezing
    /// it freezes every commit path at once and there is no call site that has
    /// to remember to check.
    ///
    /// It deliberately does not touch a window that is already open.  A commit
    /// halfway through its writes must be allowed to finish, because the rows it
    /// has already written are recorded in the manifest under a checkpoint the
    /// rollback plan knows about; killing it mid-way would leave rows the
    /// manifest describes as a complete commit.  Draining is what
    /// [`is_quiesced`](Self::is_quiesced) reports and what the freeze receipt
    /// must wait for.
    ///
    /// Idempotent: a participant that observes the freeze phase repeatedly, or
    /// restarts during it, calls this every time it looks.
    pub fn freeze_for_rollback(&self) {
        self.state.lock().expect("commit window mutex poisoned").frozen = true;
    }

    /// Admit commits again, once the rollback has finished or been abandoned.
    pub fn thaw_after_rollback(&self) {
        self.state.lock().expect("commit window mutex poisoned").frozen = false;
    }

    pub fn is_frozen(&self) -> bool {
        self.state.lock().expect("commit window mutex poisoned").frozen
    }

    /// Frozen *and* drained: no commit is running and no further one can start.
    ///
    /// Only in this state is the head byte-for-byte stable, so this -- not
    /// `is_frozen` -- is the precondition for filing a freeze receipt.  A receipt
    /// filed while a commit was still draining would tell the Coordinator the
    /// head had stopped moving while it was still being written to.
    pub fn is_quiesced(&self) -> bool {
        let state = self.state.lock().expect("commit window mutex poisoned");
        state.frozen && state.open.is_none()
    }

    fn close(&self) {
        self.state.lock().expect("commit window mutex poisoned").open = None;
    }
}

/// What a rollback needs from a node's commit path, whichever role it is.
///
/// Both recordings own a `CommitWindowClock`; this is the part of them a
/// rollback executor uses, and naming it keeps the executor from having to know
/// which role it is driving.
pub trait CommitFreeze: Send + Sync {
    /// Stop admitting commits.
    fn freeze_for_rollback(&self);
    /// Admit them again.
    fn thaw_after_rollback(&self);
    /// Frozen and drained: nothing running and nothing able to start.
    fn is_quiesced_for_rollback(&self) -> bool;
}

/// Closes the commit window when it goes out of scope.
#[must_use = "dropping the guard immediately closes the window the commit needs"]
pub struct CommitWindowGuard {
    clock: Arc<CommitWindowClock>,
}

impl CommitWindowGuard {
    /// The window this guard holds open.
    pub fn window(&self) -> CommitWindow {
        self.clock
            .peek()
            .expect("a held guard means the window is open")
    }
}

impl Drop for CommitWindowGuard {
    fn drop(&mut self) {
        self.clock.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(value: i64) -> CommitWriteTimestampUs {
        CommitWriteTimestampUs::try_from_i128(value as i128).expect("in range")
    }

    #[test]
    fn asking_for_a_timestamp_with_no_window_is_an_error() {
        // No window must never quietly mean "use the wall clock": that value is
        // exactly what a fence shadows afterwards.
        let clock = Arc::new(CommitWindowClock::new());
        assert_eq!(
            clock.require_checkpoint(100),
            Err(CommitWindowError::NoActiveWindow {
                checkpoint_id: 100
            })
        );
    }

    #[test]
    fn a_window_yields_one_timestamp_for_its_own_checkpoint() {
        let clock = Arc::new(CommitWindowClock::new());
        let _guard = clock
            .open(CommitWindow::new(100, ts(1_700_000_000_000_000)))
            .expect("no window is open");
        assert_eq!(
            clock.require_checkpoint(100),
            Ok(ts(1_700_000_000_000_000))
        );
    }

    #[test]
    fn another_checkpoint_cannot_borrow_this_window() {
        let clock = Arc::new(CommitWindowClock::new());
        let _guard = clock
            .open(CommitWindow::new(100, ts(1_700_000_000_000_000)))
            .expect("no window is open");
        assert_eq!(
            clock.require_checkpoint(101),
            Err(CommitWindowError::CheckpointMismatch {
                window: 100,
                commit: 101,
            })
        );
    }

    #[test]
    fn windows_do_not_nest() {
        let clock = Arc::new(CommitWindowClock::new());
        let _guard = clock
            .open(CommitWindow::new(100, ts(1_700_000_000_000_000)))
            .expect("no window is open");
        assert_eq!(
            clock
                .open(CommitWindow::new(101, ts(1_700_000_000_000_001)))
                .err(),
            Some(CommitWindowError::AlreadyOpen {
                open: 100,
                requested: 101,
            })
        );
    }

    #[test]
    fn a_failed_commit_does_not_leave_the_window_open() {
        // The next commit must not be able to borrow this one's timestamp, so
        // the guard has to close on the early return of a failure too.
        let clock = Arc::new(CommitWindowClock::new());
        let failed: Result<(), &str> = (|| {
            let _guard = clock
                .open(CommitWindow::new(100, ts(1_700_000_000_000_000)))
                .expect("no window is open");
            Err("this commit failed")
        })();
        assert!(failed.is_err());
        assert_eq!(clock.peek(), None);
        assert_eq!(
            clock.require_checkpoint(101),
            Err(CommitWindowError::NoActiveWindow {
                checkpoint_id: 101
            })
        );
    }

    #[test]
    fn a_reopened_window_carries_the_new_timestamp() {
        let clock = Arc::new(CommitWindowClock::new());
        {
            let _guard = clock
                .open(CommitWindow::new(100, ts(1_700_000_000_000_000)))
                .expect("no window is open");
            assert_eq!(
                clock.require_checkpoint(100).expect("open"),
                ts(1_700_000_000_000_000)
            );
        }
        let _guard = clock
            .open(CommitWindow::new(101, ts(1_700_000_000_000_050)))
            .expect("the first window closed");
        assert_eq!(
            clock.require_checkpoint(101).expect("open"),
            ts(1_700_000_000_000_050)
        );
    }

    #[test]
    fn a_frozen_clock_admits_no_new_commit() {
        let clock = Arc::new(CommitWindowClock::new());
        clock.freeze_for_rollback();
        let refused = clock.open(CommitWindow::new(100, ts(1_700_000_000_000_000)));
        assert!(
            matches!(
                refused,
                Err(CommitWindowError::FrozenForRollback { requested: 100 })
            ),
            "a frozen node must not start a commit"
        );
    }

    #[test]
    fn freezing_lets_the_commit_already_running_finish() {
        // Its rows are already recorded in the manifest under this checkpoint.
        // Cutting it off would leave the manifest describing a commit that the
        // database only half contains.
        let clock = Arc::new(CommitWindowClock::new());
        let guard = clock
            .open(CommitWindow::new(100, ts(1_700_000_000_000_000)))
            .expect("no window is open");
        clock.freeze_for_rollback();
        assert_eq!(
            clock.require_checkpoint(100).expect("still committing"),
            ts(1_700_000_000_000_000)
        );
        assert!(!clock.is_quiesced(), "a draining commit is not quiesced");
        drop(guard);
        assert!(clock.is_quiesced());
    }

    #[test]
    fn a_freeze_that_has_not_drained_is_not_a_stable_head() {
        // The distinction the freeze receipt turns on: frozen says no commit can
        // start, quiesced says none is running either.
        let clock = Arc::new(CommitWindowClock::new());
        let _guard = clock
            .open(CommitWindow::new(7, ts(9_000_000_000_000_000)))
            .expect("no window is open");
        clock.freeze_for_rollback();
        assert!(clock.is_frozen());
        assert!(!clock.is_quiesced());
    }

    #[test]
    fn an_unfrozen_idle_clock_is_not_quiesced_either() {
        // Otherwise a node that was never asked to freeze would report a stable
        // head simply because it happened to be between commits.
        let clock = Arc::new(CommitWindowClock::new());
        assert!(!clock.is_quiesced());
    }

    #[test]
    fn thawing_lets_the_chain_continue() {
        let clock = Arc::new(CommitWindowClock::new());
        clock.freeze_for_rollback();
        clock.thaw_after_rollback();
        let guard = clock.open(CommitWindow::new(88, ts(1_700_000_000_000_000)));
        assert!(guard.is_ok(), "a finished rollback must not park the node");
    }

    #[test]
    fn freezing_twice_is_the_same_as_freezing_once() {
        // A participant polls the phase in a loop and restarts during it.
        let clock = Arc::new(CommitWindowClock::new());
        clock.freeze_for_rollback();
        clock.freeze_for_rollback();
        assert!(clock.is_quiesced());
        clock.thaw_after_rollback();
        assert!(!clock.is_frozen());
    }
}
