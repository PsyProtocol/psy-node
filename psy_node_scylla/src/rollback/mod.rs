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

mod canonical_head_store;
mod commit_source_store;
mod identity;
mod key;
mod keyspace;
mod mutation;
mod raw_access;
mod registry;

pub use canonical_head_store::*;
pub use commit_source_store::*;
pub use identity::{ScyllaKeyDomain, ScyllaPhysicalTableId};
pub use keyspace::{CqlKeyspaceName, InvalidCqlKeyspaceName};
pub use key::{
    CqlPrimaryKeyFingerprint, ResolvedScyllaKey, describe_existing_key, resolve_key_for_rollback,
};
pub(crate) use key::decode_locator_canonical;
pub use raw_access::{
    RAW_SCYLLA_ACCESS_ALLOWLIST, RawScyllaAccessAllowance, RawScyllaAccessCounts,
    RawScyllaAccessScope, RawScyllaAccessViolation, inspect_raw_scylla_source,
    raw_scylla_access_allowance, require_raw_scylla_access_allowlisted,
};
pub use mutation::*;
pub use registry::*;
