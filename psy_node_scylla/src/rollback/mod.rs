//! Typed Scylla identities, primary keys, mutations, and rollback metadata.
//!
//! D-02a is intentionally descriptive: this module does not execute CQL and
//! is not connected to the current production writers yet.

mod identity;
mod key;
mod mutation;
mod registry;

pub use identity::*;
pub use key::*;
pub use mutation::*;
pub use registry::*;
