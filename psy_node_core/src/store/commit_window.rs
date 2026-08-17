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
    open: Mutex<Option<CommitWindow>>,
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
        let mut slot = self.open.lock().expect("commit window mutex poisoned");
        if let Some(existing) = *slot {
            return Err(CommitWindowError::AlreadyOpen {
                open: existing.checkpoint_id(),
                requested: window.checkpoint_id(),
            });
        }
        *slot = Some(window);
        drop(slot);
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
        *self.open.lock().expect("commit window mutex poisoned")
    }

    fn close(&self) {
        *self.open.lock().expect("commit window mutex poisoned") = None;
    }
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
}
