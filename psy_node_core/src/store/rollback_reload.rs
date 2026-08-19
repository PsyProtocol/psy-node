//! Why a Coordinator restarts itself after a rollback instead of repairing in
//! place.
//!
//! A rollback rewrites the database under a running processor.  Everything the
//! process holds in memory then describes the branch that was discarded: the
//! checkpoint-tree cache, the next checkpoint id, the pending-id counters, the
//! last committed roots, the gatherer tasks and the queue consumers they are
//! reading.  Nothing tells it so.  It plans the next block from the stale head,
//! publishes jobs for a checkpoint that no longer exists, and waits for them
//! forever without logging an error -- the failure is visible only in the
//! worker, as a proof for a checkpoint that is gone.
//!
//! ## In-place repair was tried and abandoned
//!
//! `reset_to_checkpoint` exists and rebuilds the cache and the ids, so repairing
//! in place looked like one call.  It is not.  Each layer fixed uncovered the
//! next, on a live chain:
//!
//! 1. the checkpoint-tree cache -- `reset_to_checkpoint`;
//! 2. the gathering ids, which it leaves equal to the processing ids while the
//!    block loop requires them ahead -- `set_new_unique_ids`;
//! 3. the gatherer tasks, whose handover the block flow performs every block and
//!    a repair path does not -- `channel closed`.
//!
//! Every layer is a place to be wrong, and one exercised only during rollbacks:
//! the least-tested code doing the most dangerous job.  Startup establishes all
//! of them at once, is exercised on every start and every crash, and already
//! contains the truncation a rollback needs.  Restarting reuses it; repairing in
//! place reimplements it a piece at a time.
//!
//! ## Why exit rather than return an error
//!
//! A returned error is indistinguishable from a crash to whatever restarts the
//! process, and the difference matters: this is a node reporting that it has
//! done its part and needs a fresh start, not one that failed.  A dedicated code
//! lets a supervisor restart it without also masking real crashes behind
//! `Restart=always`, and lets an operator reading logs tell the two apart.

/// Exit status a processor uses to ask to be restarted after a rollback.
///
/// 75 is `EX_TEMPFAIL` from `sysexits.h`: the operation could not be completed
/// now and should be retried.  Borrowing a conventional code rather than
/// inventing one means an unfamiliar supervisor still treats it sensibly.
pub const EXIT_CODE_ROLLBACK_RELOAD: i32 = 75;
