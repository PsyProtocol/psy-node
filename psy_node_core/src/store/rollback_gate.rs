//! Whether a rollback is running, for the side that answers questions about the
//! chain.
//!
//! A rollback has intermediate states -- frozen, archiving, deleting, restoring,
//! verifying -- and during them the database is not a description of any branch
//! anybody should be told about.  Answering straight through them hands out
//! values that are about to stop being true.
//!
//! That is not hypothetical.  A Realm asked the Coordinator where its root was,
//! nine seconds after undoing its own share of a rollback, and was told
//! checkpoint 222.  It caught up to 222 and committed it again under the new
//! epoch.  222 belonged to the branch being discarded -- the rollback removed
//! that version correctly, the surviving ones stop at 201 -- and the Realm had
//! simply asked while the delete was still running.  It then failed
//! `Realm Root mismatch` once a second for as long as it ran.
//!
//! The Realm had just reconciled and restarted, so it knew a rollback had
//! happened, and believed the answer anyway.  Asking callers to be careful does
//! not work.  The judgement belongs on the side that knows, which is this one.
//!
//! A flag rather than a read per request, because the answer changes a handful
//! of times an hour and is asked thousands of times.  It is set by whoever
//! watches the control row; a node that never installs a watcher never refuses,
//! which is how it behaved before this existed.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

static GATE: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Hand this process the flag a watcher will keep up to date.
///
/// Called once, by whoever can see the Coordinator's control row.  A second
/// call is ignored: two watchers would agree, and failing startup over which
/// one arrived first would be worse than either answer.
pub fn install_rollback_gate(gate: Arc<AtomicBool>) {
    let _ = GATE.set(gate);
}

/// Whether a rollback is in flight right now.
///
/// False when nothing was installed, which is the behaviour every node had
/// before this: answer, and let the caller sort it out.
pub fn is_rolling_back() -> bool {
    GATE.get().is_some_and(|gate| gate.load(Ordering::Relaxed))
}

/// The error an answer is refused with.
///
/// Typed, so a caller can wait for the rollback rather than treating it as the
/// chain being broken -- the two need opposite responses and read alike in a
/// string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnswerRefusedDuringRollback;

impl std::fmt::Display for AnswerRefusedDuringRollback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "a rollback is running: this answer would describe a branch that is being discarded. \
             Ask again once it has finished",
        )
    }
}

impl std::error::Error for AnswerRefusedDuringRollback {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_a_watcher_nothing_is_refused() {
        // A node that never installs one behaves exactly as it did before this
        // module existed, which is what makes it safe to add.
        assert!(!is_rolling_back());
    }
}
