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
pub mod realm_commit_recording;
pub mod realm_recording_flow;
pub mod rollback_control;
pub mod rollback_gate;
pub mod transient_failure;
pub mod rollback_coordination;
pub mod realm_self_rollback;
pub mod realm_sync_epoch;
pub mod rollback_event;
pub mod rollback_participants;
pub mod rollback_reload;
pub mod rollback_plan;
pub mod rollback_request;
pub mod timestamp;
pub mod verification_journal;
