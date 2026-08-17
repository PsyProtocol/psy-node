//! Feeds the open commit window's timestamp to every statement the session sends.
//!
//! The driver takes a statement's own timestamp when it has one and otherwise
//! calls the session's generator (`connection.rs`: `statement.get_timestamp()
//! .or_else(get_timestamp_from_gen)`), and it does so in the connection layer,
//! below prepared statements, unprepared statements and batches alike.  That
//! makes this the one place a write cannot get past without being stamped.
//!
//! Going through the generator rather than stamping each adapter is a deliberate
//! trade.  A commit's rows are written by seven adapter families through a few
//! dozen insert variants; stamping them one by one invites exactly the failure
//! that has already bitten this work three times -- an omission that cannot fail,
//! because a missed adapter silently falls back to a server clock and nothing
//! reports it.  Here there is nothing to miss: every row of a commit shares the
//! window's timestamp by construction, which is also what keeps the commit atomic
//! under last-write-wins.
//!
//! ## What this changes for writes outside a commit
//!
//! `TimestampGenerator::next_timestamp` returns an `i64`; it cannot decline.  So
//! installing one moves *every* write on this session -- edge handlers, query
//! paths, Realm -- from a server-assigned timestamp to a client-assigned one.
//! Both are wall-clock microseconds and both come from a single process per node,
//! so the scale is unchanged; what changes is which machine reads the clock.  The
//! fallback below therefore delegates to the driver's own
//! `MonotonicTimestampGenerator`, which is the behaviour its authors intend for
//! client-side stamping and which already handles a clock that steps backwards.

use std::sync::Arc;

use psy_node_core::store::commit_window::CommitWindowClock;
use scylla::policies::timestamp_generator::{MonotonicTimestampGenerator, TimestampGenerator};

/// Stamps statements with the open commit window, or the monotonic clock when no
/// commit is in progress.
#[derive(Debug)]
pub struct CommitWindowTimestampGenerator {
    clock: Arc<CommitWindowClock>,
    outside_commit: MonotonicTimestampGenerator,
}

impl CommitWindowTimestampGenerator {
    pub fn new(clock: Arc<CommitWindowClock>) -> Self {
        Self {
            clock,
            outside_commit: MonotonicTimestampGenerator::new(),
        }
    }
}

impl TimestampGenerator for CommitWindowTimestampGenerator {
    fn next_timestamp(&self) -> i64 {
        match self.clock.peek() {
            // Every row of the commit, in every table, on every statement kind.
            // Not "the next timestamp" but "this commit's timestamp": advancing
            // it per statement would split one commit across several points on
            // the conflict-resolution axis, and a reader could then see part of
            // it win and part of it lose.
            Some(window) => window.timestamp().as_i64(),
            None => self.outside_commit.next_timestamp(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_node_core::store::commit_window::CommitWindow;
    use psy_node_core::store::timestamp::CommitWriteTimestampUs;

    fn ts(value: i64) -> CommitWriteTimestampUs {
        CommitWriteTimestampUs::try_from_i128(value as i128).expect("in range")
    }

    #[test]
    fn every_statement_in_a_commit_gets_the_same_timestamp() {
        let clock = Arc::new(CommitWindowClock::new());
        let generator = CommitWindowTimestampGenerator::new(clock.clone());
        let _guard = clock
            .open(CommitWindow::new(41, ts(1_700_000_000_000_000)))
            .expect("no window is open");
        // A commit issues many statements; all of them must land on one point.
        let stamps: Vec<i64> = (0..8).map(|_| generator.next_timestamp()).collect();
        assert!(stamps.iter().all(|s| *s == 1_700_000_000_000_000));
    }

    #[test]
    fn writes_outside_a_commit_still_get_a_clock() {
        // Edge handlers and query paths share this session and must keep working;
        // failing closed here would take them down rather than protect anything,
        // since they never write a table a rollback deletes from.
        let clock = Arc::new(CommitWindowClock::new());
        let generator = CommitWindowTimestampGenerator::new(clock);
        let first = generator.next_timestamp();
        let second = generator.next_timestamp();
        assert!(first > 0);
        assert!(second > first, "the fallback must not go backwards");
    }

    #[test]
    fn the_window_takes_over_and_hands_back() {
        let clock = Arc::new(CommitWindowClock::new());
        let generator = CommitWindowTimestampGenerator::new(clock.clone());
        let before = generator.next_timestamp();
        {
            let _guard = clock
                .open(CommitWindow::new(7, ts(9_000_000_000_000_000)))
                .expect("no window is open");
            assert_eq!(generator.next_timestamp(), 9_000_000_000_000_000);
        }
        let after = generator.next_timestamp();
        assert_ne!(after, 9_000_000_000_000_000);
        assert!(after > before);
    }
}
