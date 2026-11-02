//! One tick's input: the rows read from one coherent Envio snapshot, and the
//! cursors (committed boundaries) the next read starts from.

use std::collections::{BTreeMap, BTreeSet};

use psy_bridge_reader_api::{DepositRow, FinalizedBatchRow, WithdrawalClaimRow};

use crate::tree::hash::Hash;

/// Everything one read of Envio returned, all from the same snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct TickData {
    pub identity: Identity,
    pub started_unix_ms: u64,
    pub progress: Vec<ChainProgress>,
    pub metas: Vec<TreeMetaRow>,
    /// Keyed by chain_index.
    pub deposits: BTreeMap<u64, Vec<DepositWithLeaf>>,
    /// Keyed by chain_id.
    pub claims: BTreeMap<u64, Vec<WithdrawalClaimRow>>,
    /// Keyed by chain_id.
    pub batches: BTreeMap<u64, Vec<FinalizedBatchRow>>,
    /// Whether any follow read returned more than the row limit.
    pub truncated: bool,
    /// The `Cursors::skip` this read honoured: no deposit rows were read for
    /// these chain indexes.
    pub skipped: BTreeSet<u64>,
}

/// Identifies the Envio schema instance (the oids change when Envio drops and
/// re-creates its schema).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub chains_oid: i64,
    pub deposit_oid: i64,
}

/// One `envio_chains` row. `progress_block` is -1 before the first batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainProgress {
    pub chain_id: u64,
    pub progress_block: i64,
    pub max_reorg_depth: u64,
}

/// One `DepositTreeMeta` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeMetaRow {
    pub chain_index: u64,
    pub last_count: u64,
    pub root: Hash,
}

/// A deposit and its tree leaf.
#[derive(Debug, Clone, PartialEq)]
pub struct DepositWithLeaf {
    pub row: DepositRow,
    pub leaf: Hash,
    /// The `DepositLeaf` row's own `deposit_index` and `chain_id`. The source
    /// pairs deposits and leaves by position; `Model::apply` checks these.
    pub leaf_deposit_index: u64,
    pub leaf_chain_id: u64,
    pub leaf_block_number: u64,
}

/// The committed boundaries a read continues from. `claims` and `batches` are
/// keyed by chain_id and hold the last committed `(block_number, id)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cursors {
    /// Keyed by chain_index.
    pub deposits: BTreeMap<u64, DepositCursor>,
    pub claims: BTreeMap<u64, (u64, String)>,
    pub batches: BTreeMap<u64, (u64, String)>,
    /// Chain indexes whose deposits the read leaves out while their reload
    /// backs off.
    pub skip: BTreeSet<u64>,
}

/// The committed boundary of one chain_index.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DepositCursor {
    pub local_count: u64,
    pub next_deposit_index: u64,
}
