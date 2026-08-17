pub mod traits;
pub mod typed;

// R1 rollback control-plane contract (psy-memory/rollback/design-r1.md).
// These are driver-independent models: no CQL, no session, no I/O.  The Scylla
// adapters that satisfy the traits land separately.
pub mod authority_commit;
pub mod canonical_head;
pub mod commit_planner;
pub mod commit_recording_flow;
pub mod commit_window;
pub mod coordinator_commit_source;
pub mod manifest_intent;
pub mod manifest_lifecycle;
pub mod manifest_record;
pub mod manifest_store;
pub mod rollback_control;
pub mod timestamp;
