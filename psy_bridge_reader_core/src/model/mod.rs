//! The Reader's in-memory model of the Envio deposit, claim and batch tables.

pub mod tick;

pub use tick::{ChainProgress, Cursors, DepositCursor, DepositWithLeaf, Identity, TickData, TreeMetaRow};
