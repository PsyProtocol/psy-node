pub mod traits;
pub mod typed;

// R1 rollback control-plane contract (psy-memory/rollback/design-r1.md).
// These are driver-independent models: no CQL, no session, no I/O.  The Scylla
// adapters that satisfy the traits land separately.
pub mod canonical_head;
pub mod coordinator_commit_source;
pub mod rollback_control;
pub mod timestamp;
