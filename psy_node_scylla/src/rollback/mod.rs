//! Typed Scylla identities, primary keys, mutations, and rollback metadata.
//!
//! D-02a remains the registry baseline. G0-06 provides representative fence
//! adapters and D-02T1 adds the closed checkpoint-keyed KIV family, but neither
//! is connected to production setup or current writers yet.

mod canonical_head_prototype;
mod checkpoint_kiv;
mod rollback_admission;
mod identity;
mod key;
mod mutation;
mod confinement;
mod namespace;
mod namespace_prototype;
mod raw_access;
mod replay;
mod timestamp_prototype;
mod timestamped;
mod registry;

pub use canonical_head_prototype::*;
pub use checkpoint_kiv::*;
pub use rollback_admission::*;
pub use identity::*;
pub use key::*;
pub use mutation::*;
pub use confinement::*;
pub use namespace::*;
pub use namespace_prototype::*;
pub use raw_access::*;
pub use replay::*;
pub use timestamp_prototype::*;
pub use timestamped::*;
pub use registry::*;
