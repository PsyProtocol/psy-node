//! One chain_id's withdrawal claims and finalized batches: an append-only
//! committed part in `(block_number, id)` order plus a per-tick window, the
//! same shape as a chain index's deposits.

use std::sync::Arc;

use parking_lot::{RwLock, RwLockReadGuard};
use psy_bridge_reader_api::{FinalizedBatchRow, WithdrawalClaimRow};

#[cfg(test)]
use crate::model::chain::index_walk_bytes;
use crate::model::chain::{index_push, strings_bytes, table_bytes, vec_bytes, RowIndex};

fn claim_heap_bytes(c: &WithdrawalClaimRow) -> u64 {
    strings_bytes(&[&c.id, &c.nullifier, &c.recipient, &c.token, &c.amount, &c.tx_hash])
}

fn batch_heap_bytes(b: &FinalizedBatchRow) -> u64 {
    strings_bytes(&[&b.id, &b.finalized_checkpoint_id, &b.deposit_tree_root, &b.withdrawal_tree_root, &b.tx_hash])
}

/// Appends clones of `claims` and `batches`, indexing each claim by nullifier
/// at its position; returns the capacity of the new strings, keys and
/// position lists.
fn push_rows(
    out_claims: &mut Vec<WithdrawalClaimRow>,
    by_nullifier: &mut RowIndex,
    out_batches: &mut Vec<FinalizedBatchRow>,
    claims: &[WithdrawalClaimRow],
    batches: &[FinalizedBatchRow],
) -> u64 {
    let mut heap_bytes = 0;
    out_claims.reserve(claims.len());
    out_batches.reserve(batches.len());
    for c in claims {
        let seq = u32::try_from(out_claims.len()).expect("at most 2^32 claims per chain_id");
        let row = c.clone();
        heap_bytes += claim_heap_bytes(&row) + index_push(by_nullifier, &row.nullifier, seq);
        out_claims.push(row);
    }
    for b in batches {
        let row = b.clone();
        heap_bytes += batch_heap_bytes(&row);
        out_batches.push(row);
    }
    heap_bytes
}

/// The vectors and the table at their allocated capacity.
fn rows_bytes(claims: &Vec<WithdrawalClaimRow>, by_nullifier: &RowIndex, batches: &Vec<FinalizedBatchRow>) -> u64 {
    vec_bytes(claims) + vec_bytes(batches) + table_bytes::<String, Vec<u32>>(by_nullifier.capacity())
}

#[cfg(test)]
fn rows_walk_bytes(claims: &Vec<WithdrawalClaimRow>, by_nullifier: &RowIndex, batches: &Vec<FinalizedBatchRow>) -> u64 {
    vec_bytes(claims)
        + claims.iter().map(claim_heap_bytes).sum::<u64>()
        + vec_bytes(batches)
        + batches.iter().map(batch_heap_bytes).sum::<u64>()
        + index_walk_bytes(by_nullifier)
}

/// Claims and batches at or below the committed safe block. A claim's
/// sequence number is its position in `claims`.
#[derive(Default)]
pub(crate) struct CommittedClaims {
    pub(crate) claims: Vec<WithdrawalClaimRow>,
    pub(crate) by_nullifier: RowIndex,
    pub(crate) batches: Vec<FinalizedBatchRow>,
    /// Kept as rows are appended, like `CommittedChain`'s.
    heap_bytes: u64,
}

impl CommittedClaims {
    pub(crate) fn append(&mut self, claims: &[WithdrawalClaimRow], batches: &[FinalizedBatchRow]) {
        self.heap_bytes += push_rows(&mut self.claims, &mut self.by_nullifier, &mut self.batches, claims, batches);
    }

    pub(crate) fn resident_bytes(&self) -> u64 {
        self.heap_bytes + rows_bytes(&self.claims, &self.by_nullifier, &self.batches)
    }

    #[cfg(test)]
    pub(crate) fn walk_bytes(&self) -> u64 {
        rows_walk_bytes(&self.claims, &self.by_nullifier, &self.batches)
    }
}

/// The committed part of one chain_id, shared by every view of it.
#[derive(Default)]
pub(crate) struct ClaimData {
    pub(crate) committed: RwLock<CommittedClaims>,
}

/// Claims and batches above the committed boundary, rebuilt each tick.
#[derive(Default)]
pub(crate) struct ClaimWindow {
    pub(crate) claims: Vec<WithdrawalClaimRow>,
    pub(crate) by_nullifier: RowIndex,
    pub(crate) batches: Vec<FinalizedBatchRow>,
    /// Bytes of everything above, computed once by `build`.
    pub(crate) resident_bytes: u64,
}

impl ClaimWindow {
    pub(crate) fn build(claims: &[WithdrawalClaimRow], batches: &[FinalizedBatchRow]) -> ClaimWindow {
        let mut w = ClaimWindow::default();
        let heap_bytes = push_rows(&mut w.claims, &mut w.by_nullifier, &mut w.batches, claims, batches);
        w.resident_bytes = heap_bytes + rows_bytes(&w.claims, &w.by_nullifier, &w.batches);
        w
    }

    pub(crate) fn holds(&self, claims: &[WithdrawalClaimRow], batches: &[FinalizedBatchRow]) -> bool {
        self.claims == claims && self.batches == batches
    }

    #[cfg(test)]
    pub(crate) fn walk_bytes(&self) -> u64 {
        rows_walk_bytes(&self.claims, &self.by_nullifier, &self.batches)
    }
}

/// One chain_id's claims and batches as one published `View` sees them.
#[derive(Clone)]
pub struct ClaimChainView {
    pub(crate) data: Arc<ClaimData>,
    /// High-water sequence: committed claims at or past it are not in this view.
    pub(crate) committed_claims: usize,
    pub(crate) committed_batches: usize,
    pub(crate) window: Arc<ClaimWindow>,
    pub(crate) ready: Result<(), String>,
}

impl ClaimChainView {
    pub(crate) fn not_ready(data: Arc<ClaimData>, reason: String) -> ClaimChainView {
        ClaimChainView { data, committed_claims: 0, committed_batches: 0, window: Arc::new(ClaimWindow::default()), ready: Err(reason) }
    }

    pub(crate) fn read(&self) -> ClaimRead<'_> {
        ClaimRead { committed: self.data.committed.read(), view: self }
    }

    pub(crate) fn batches_len(&self) -> usize {
        self.committed_batches + self.window.batches.len()
    }
}

/// A claim view under one hold of its committed read lock.
pub(crate) struct ClaimRead<'a> {
    committed: RwLockReadGuard<'a, CommittedClaims>,
    view: &'a ClaimChainView,
}

impl ClaimRead<'_> {
    /// Claim `i` in `(block_number, id)` order; requires `i < claims_len()`.
    pub(crate) fn claim(&self, i: usize) -> &WithdrawalClaimRow {
        let cl = self.view.committed_claims;
        if i < cl { &self.committed.claims[i] } else { &self.view.window.claims[i - cl] }
    }

    /// Batch `i` in `(block_number, id)` order; requires `i < batches_len()`.
    pub(crate) fn batch(&self, i: usize) -> &FinalizedBatchRow {
        let cl = self.view.committed_batches;
        if i < cl { &self.committed.batches[i] } else { &self.view.window.batches[i - cl] }
    }

    /// Every claim of this nullifier in the view, in order.
    pub(crate) fn by_nullifier<'b>(&'b self, nullifier: &str) -> impl Iterator<Item = &'b WithdrawalClaimRow> + 'b {
        let cl = self.view.committed_claims;
        let committed = self.committed.by_nullifier.get(nullifier).map_or(&[][..], Vec::as_slice);
        let window = self.view.window.by_nullifier.get(nullifier).map_or(&[][..], Vec::as_slice);
        committed
            .iter()
            .map(|p| *p as usize)
            .filter(move |p| *p < cl)
            .chain(window.iter().map(move |p| cl + *p as usize))
            .map(move |i| self.claim(i))
    }
}
