//! Read-only access to the Envio database: one coherent snapshot per tick.

use std::future::Future;

use crate::model::{Cursors, TickData};

pub mod guard;
pub mod pg;

pub use pg::{PgConfig, PgSource};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    /// The database cannot be reached or a statement failed transiently.
    #[error("Envio database unavailable: {0}")]
    Unavailable(String),
    /// A table, column or index the Reader needs is missing or unreadable.
    #[error("Envio schema missing: {0}")]
    SchemaMissing(String),
    /// A row does not have the expected shape or value range.
    #[error("Envio row decode failed: {0}")]
    Decode(String),
}

/// Where a tick's rows come from. Used only through generics, never as `dyn`.
pub trait EnvioSource: Send {
    /// Reads every row past `cursors` (at most `max_rows` per follow read) from
    /// one snapshot.
    fn read_tick(
        &mut self,
        cursors: &Cursors,
        max_rows: usize,
    ) -> impl Future<Output = Result<TickData, SourceError>> + Send;
}
