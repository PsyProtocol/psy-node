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
mod realm_commit_planner;
mod realm_control_plane;
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
pub use realm_commit_planner::*;
pub use realm_control_plane::*;
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
