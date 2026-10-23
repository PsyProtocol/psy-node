//! One chain_id's withdrawal claims and finalized batches: an append-only
//! committed part in `(block_number, id)` order plus a per-tick window, the
//! same shape as a chain index's deposits.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::{RwLock, RwLockReadGuard};
use psy_bridge_reader_api::{FinalizedBatchRow, WithdrawalClaimRow};

use crate::model::chain::RowIndex;

/// Claims and batches at or below the committed safe block. A claim's
/// sequence number is its position in `claims`.
#[derive(Default)]
pub(crate) struct CommittedClaims {
    pub(crate) claims: Vec<WithdrawalClaimRow>,
    pub(crate) by_nullifier: RowIndex,
    pub(crate) batches: Vec<FinalizedBatchRow>,
}

impl CommittedClaims {
    pub(crate) fn append(&mut self, claims: &[WithdrawalClaimRow], batches: &[FinalizedBatchRow]) {
        for c in claims {
            let seq = u32::try_from(self.claims.len()).expect("at most 2^32 claims per chain_id");
            self.by_nullifier.entry(c.nullifier.clone()).or_default().push(seq);
            self.claims.push(c.clone());
        }
        self.batches.extend_from_slice(batches);
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
}

impl ClaimWindow {
    pub(crate) fn build(claims: &[WithdrawalClaimRow], batches: &[FinalizedBatchRow]) -> ClaimWindow {
        let mut by_nullifier: RowIndex = HashMap::new();
        for (k, c) in claims.iter().enumerate() {
            by_nullifier.entry(c.nullifier.clone()).or_default().push(k as u32);
        }
        ClaimWindow { claims: claims.to_vec(), by_nullifier, batches: batches.to_vec() }
    }

    pub(crate) fn holds(&self, claims: &[WithdrawalClaimRow], batches: &[FinalizedBatchRow]) -> bool {
        self.claims == claims && self.batches == batches
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
