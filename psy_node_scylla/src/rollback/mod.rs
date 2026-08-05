//! Typed Scylla identities, primary keys, mutations, and rollback metadata.
//!
//! D-02a remains descriptive. The isolated G0-06 representative adapter can
//! prepare and execute CQL when explicitly constructed by a harness, but it is
//! not connected to production setup or current writers.

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
