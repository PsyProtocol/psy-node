//! Typed Scylla storage identities, keys, and rollback metadata.
//!
//! This is the R1 foundation described in `psy-memory/rollback/design-r1.md`
//! §2.1.  It carries the four modules whose dependency closure is clean:
//! `identity` (physical table / key-domain identity), `registry` (per-table
//! rollback contract), `key` (typed key resolution) and `raw_access` (the
//! `scylla::Session` confinement allowlist).
//!
//! Hard constraint (design-r1 D8): the typed write core must never depend on a
//! writer lifecycle, schema-migration, cutover or deployment type.  The spike
//! coupled `mutation`/`timestamped` to `BranchExactWriterPrepared`, which grew
//! the 586-line write core into a 21,399-line closure.  `tests/module_boundary.rs`
//! asserts that this does not happen again.

mod authority_timestamp_store;
mod canonical_head_store;
mod commit_planner_scylla;
mod commit_window_generator;
mod commit_source_store;
mod control_plane;
mod identity;
mod key;
mod keyspace;
mod manifest_artifact_store;
mod manifest_locator;
mod manifest_record_store;
mod mutation;
mod mutation_sink;
mod raw_access;
mod rollback_floor_store;
mod event_store;
mod realm_sync_epoch;
mod restore_executor;
mod participant_view;
mod realm_commit_planner;
mod realm_control_plane;
mod realm_rollback_executor;
mod registry;
mod archive_store;
mod delete_executor;
mod rollback_executor;
mod row_image;
mod verification_journal;

pub use authority_timestamp_store::*;
pub use canonical_head_store::*;
pub use commit_planner_scylla::*;
pub use commit_window_generator::*;
pub use archive_store::*;
pub use delete_executor::*;
pub use rollback_executor::*;
pub use event_store::*;
pub use realm_sync_epoch::*;
pub use restore_executor::*;
pub use participant_view::*;
pub use realm_commit_planner::*;
pub use realm_control_plane::*;
pub use realm_rollback_executor::*;
pub use row_image::*;
pub use verification_journal::*;
pub use commit_source_store::*;
pub use control_plane::*;
pub use identity::{ScyllaKeyDomain, ScyllaPhysicalTableId, UnknownScyllaPhysicalTableId};
pub use keyspace::{CqlKeyspaceName, InvalidCqlKeyspaceName};
pub use manifest_artifact_store::*;
pub use manifest_locator::*;
pub use manifest_record_store::*;
pub use key::{
    CqlPrimaryKeyFingerprint, ResolvedScyllaKey, describe_existing_key, resolve_key_for_rollback,
};
pub use key::decode_locator_canonical;
pub use raw_access::{
    RAW_SCYLLA_ACCESS_ALLOWLIST, RawScyllaAccessAllowance, RawScyllaAccessCounts,
    RawScyllaAccessScope, RawScyllaAccessViolation, inspect_raw_scylla_source,
    raw_scylla_access_allowance, require_raw_scylla_access_allowlisted,
};
pub use mutation::*;
pub use mutation_sink::*;
pub use registry::*;
pub use rollback_floor_store::*;

/// Wait for the commit that was already running when the freeze landed.
///
/// Freezing refuses new commits but lets the running one finish, so between the
/// two there is a window in which the head is still being written.  A plan built
/// in that window would describe a commit that grew after it was read, and the
/// archive taken from it would be short by however much landed afterwards.
///
/// Bounded rather than unbounded: a commit that has not finished in this long is
/// not draining, it is stuck, and a rollback that waits forever for it holds the
/// whole participant set frozen with no way to tell why.
pub async fn drain_in_flight_commit(
    recording: &dyn psy_node_core::store::commit_window::CommitFreeze,
) -> anyhow::Result<()> {
    const POLL: std::time::Duration = std::time::Duration::from_millis(50);
    const LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

    let started = std::time::Instant::now();
    while !recording.is_quiesced_for_rollback() {
        if started.elapsed() >= LIMIT {
            anyhow::bail!(
                "a commit was still in flight {}s after this node froze; the head has not \
                 stopped moving, so no freeze receipt may be filed for it",
                LIMIT.as_secs()
            );
        }
        tokio::time::sleep(POLL).await;
    }
    Ok(())
}

/// How long a barrier waits for the participants it is missing.
///
/// A barrier is a rendezvous.  Reading the receipt table once and failing if it
/// is incomplete turns it into a race, and one the Coordinator always wins: it
/// publishes the phase and reads in the same breath, while a Realm has to
/// notice the phase, plan its own share and archive it before it has anything
/// to file.  With a participant set of one that never showed -- the Coordinator
/// files its own receipt and the barrier is met immediately -- which is why it
/// survived until a Realm joined the set.
///
/// Bounded, because the alternative to failing is not waiting forever: a
/// participant that is never coming leaves the chain frozen, and an operator
/// needs to be told rather than left watching a process that looks busy.
pub fn barrier_wait_limit() -> std::time::Duration {
    std::time::Duration::from_secs(
        std::env::var("PSY_ROLLBACK_BARRIER_WAIT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(180),
    )
}

/// Poll interval while a barrier waits.  Short relative to how long a
/// participant takes to archive, so the wait is bounded by the slow participant
/// rather than by this.
pub const BARRIER_POLL: std::time::Duration = std::time::Duration::from_millis(500);
