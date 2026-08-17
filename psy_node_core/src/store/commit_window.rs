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
//! So the window is ambient state on the store, and the safety comes from
//! failing closed instead: a commit-path table written with no window open is an
//! error, never a silent fall back to the server clock.  That matters because the
//! silent case is unrecoverable in a specific way -- see below.
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
use std::sync::Mutex;

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
    /// A table on the recorded commit path was written outside any commit.
    ///
    /// Failing here is the whole design: the alternative is the server clock,
    /// which is exactly the value that goes silently missing after a fence.
    NoActiveWindow { physical_table: u16 },
    /// A commit-path write named a different checkpoint than the open window.
    ///
    /// Either two commits are running at once or a stale write escaped its own
    /// commit; both would stamp rows with a timestamp that is not theirs.
    CheckpointMismatch {
        physical_table: u16,
        window: u64,
        write: u64,
    },
    /// A second window was opened while one was still open.  Commits are
    /// serialised by construction, so this means the caller lost track of one.
    AlreadyOpen { open: u64, requested: u64 },
}

impl fmt::Display for CommitWindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoActiveWindow { physical_table } => write!(
                f,
                "physical table {physical_table} is on the recorded commit path but was written \
                 with no commit window open, so its rows would carry a server clock timestamp"
            ),
            Self::CheckpointMismatch {
                physical_table,
                window,
                write,
            } => write!(
                f,
                "physical table {physical_table} wrote checkpoint {write} while the open commit \
                 window belongs to checkpoint {window}"
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
    pub fn open(&self, window: CommitWindow) -> Result<CommitWindowGuard<'_>, CommitWindowError> {
        let mut slot = self.open.lock().expect("commit window mutex poisoned");
        if let Some(existing) = *slot {
            return Err(CommitWindowError::AlreadyOpen {
                open: existing.checkpoint_id(),
                requested: window.checkpoint_id(),
            });
        }
        *slot = Some(window);
        Ok(CommitWindowGuard { clock: self })
    }

    /// The timestamp for a row that carries the checkpoint it belongs to.
    ///
    /// Comparing the two is nearly free -- every versioned row already has the
    /// column -- and it turns a concurrent writer that wandered into the window
    /// from a silent mis-stamp into an error.
    pub fn require_for_checkpoint(
        &self,
        physical_table: u16,
        checkpoint_id: u64,
    ) -> Result<CommitWriteTimestampUs, CommitWindowError> {
        let window = self.require_open(physical_table)?;
        if window.checkpoint_id() != checkpoint_id {
            return Err(CommitWindowError::CheckpointMismatch {
                physical_table,
                window: window.checkpoint_id(),
                write: checkpoint_id,
            });
        }
        Ok(window.timestamp())
    }

    /// The timestamp for a row with no checkpoint column to compare against.
    ///
    /// Only for rows that genuinely have none -- the singletons and cursors that
    /// are overwritten in place.  Anything with a checkpoint must use
    /// [`require_for_checkpoint`](Self::require_for_checkpoint); reaching for
    /// this instead would drop the one cross-check available.
    pub fn require_unversioned(
        &self,
        physical_table: u16,
    ) -> Result<CommitWriteTimestampUs, CommitWindowError> {
        Ok(self.require_open(physical_table)?.timestamp())
    }

    /// The open window, without consuming it.  For assertions and diagnostics.
    pub fn peek(&self) -> Option<CommitWindow> {
        *self.open.lock().expect("commit window mutex poisoned")
    }

    fn require_open(&self, physical_table: u16) -> Result<CommitWindow, CommitWindowError> {
        self.open
            .lock()
            .expect("commit window mutex poisoned")
            .ok_or(CommitWindowError::NoActiveWindow { physical_table })
    }

    fn close(&self) {
        *self.open.lock().expect("commit window mutex poisoned") = None;
    }
}

/// Closes the commit window when it goes out of scope.
#[must_use = "dropping the guard immediately closes the window the commit needs"]
pub struct CommitWindowGuard<'a> {
    clock: &'a CommitWindowClock,
}

impl CommitWindowGuard<'_> {
    /// The window this guard holds open.
    pub fn window(&self) -> CommitWindow {
        self.clock
            .peek()
            .expect("a held guard means the window is open")
    }
}

impl Drop for CommitWindowGuard<'_> {
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
    fn a_write_outside_any_window_is_an_error() {
        // The point of the whole module: no window must never mean "use the
        // server clock", because that value is what a fence silently shadows.
        let clock = CommitWindowClock::new();
        assert_eq!(
            clock.require_for_checkpoint(7, 100),
            Err(CommitWindowError::NoActiveWindow { physical_table: 7 })
        );
        assert_eq!(
            clock.require_unversioned(7),
            Err(CommitWindowError::NoActiveWindow { physical_table: 7 })
        );
    }

    #[test]
    fn every_row_of_one_commit_gets_the_same_timestamp() {
        let clock = CommitWindowClock::new();
        let _guard = clock
            .open(CommitWindow::new(100, ts(1_700_000_000_000_000)))
            .expect("no window is open");
        let first = clock.require_for_checkpoint(1, 100).expect("open");
        let second = clock.require_for_checkpoint(2, 100).expect("open");
        let singleton = clock.require_unversioned(3).expect("open");
        assert_eq!(first, second);
        assert_eq!(first, singleton);
    }

    #[test]
    fn a_row_from_another_checkpoint_is_refused() {
        let clock = CommitWindowClock::new();
        let _guard = clock
            .open(CommitWindow::new(100, ts(1_700_000_000_000_000)))
            .expect("no window is open");
        assert_eq!(
            clock.require_for_checkpoint(9, 101),
            Err(CommitWindowError::CheckpointMismatch {
                physical_table: 9,
                window: 100,
                write: 101,
            })
        );
    }

    #[test]
    fn windows_do_not_nest() {
        let clock = CommitWindowClock::new();
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
        let clock = CommitWindowClock::new();
        let failed: Result<(), &str> = (|| {
            let _guard = clock
                .open(CommitWindow::new(100, ts(1_700_000_000_000_000)))
                .expect("no window is open");
            Err("this commit failed")
        })();
        assert!(failed.is_err());
        assert_eq!(clock.peek(), None);
        assert_eq!(
            clock.require_unversioned(1),
            Err(CommitWindowError::NoActiveWindow { physical_table: 1 })
        );
    }

    #[test]
    fn a_reopened_window_carries_the_new_timestamp() {
        let clock = CommitWindowClock::new();
        {
            let _guard = clock
                .open(CommitWindow::new(100, ts(1_700_000_000_000_000)))
                .expect("no window is open");
            assert_eq!(
                clock.require_for_checkpoint(1, 100).expect("open"),
                ts(1_700_000_000_000_000)
            );
        }
        let _guard = clock
            .open(CommitWindow::new(101, ts(1_700_000_000_000_050)))
            .expect("the first window closed");
        assert_eq!(
            clock.require_for_checkpoint(1, 101).expect("open"),
            ts(1_700_000_000_000_050)
        );
    }
}
