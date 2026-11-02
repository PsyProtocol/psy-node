//! One chain index: its committed deposits, leaves and tree, the window of rows
//! above the committed boundary, and the view of both that a read uses.
//!
//! The committed part only grows. A `ChainView` records how much of it it
//! covers (`committed_len`) and ignores every committed entry at or past that
//! length, so a view taken before a promotion stays valid without a copy.

use std::collections::HashMap;
use std::mem::size_of;
use std::sync::Arc;

use parking_lot::{RwLock, RwLockReadGuard};
use psy_bridge_reader_api::DepositRow;

use crate::model::tick::{DepositWithLeaf, TreeMetaRow};
use crate::tree::hash::{zero, Hash};
use crate::tree::snapshot::{completed_nodes, TreeSource};
use crate::tree::upper::UpperLevels;

/// Positions of one key's rows, in row order.
pub(crate) type RowIndex = HashMap<String, Vec<u32>>;

/// Bytes of a hash table's own allocation at `capacity`: hashbrown keeps one
/// control byte per bucket and fills at most 7/8 of its buckets.
pub(crate) fn table_bytes<K, V>(capacity: usize) -> u64 {
    (capacity * (size_of::<(K, V)>() + 1) * 8 / 7) as u64
}

pub(crate) fn vec_bytes<T>(v: &Vec<T>) -> u64 {
    (v.capacity() * size_of::<T>()) as u64
}

pub(crate) fn strings_bytes(strings: &[&String]) -> u64 {
    strings.iter().map(|s| s.capacity() as u64).sum()
}

fn deposit_heap_bytes(r: &DepositRow) -> u64 {
    strings_bytes(&[&r.id, &r.shield_address, &r.token, &r.l2_token_contract_id, &r.amount, &r.note_commitment, &r.leaf_hash, &r.tx_hash])
}

/// Adds `pos` under `key`; returns the bytes it added outside the table itself.
pub(crate) fn index_push(index: &mut RowIndex, key: &str, pos: u32) -> u64 {
    if let Some(positions) = index.get_mut(key) {
        let before = vec_bytes(positions);
        positions.push(pos);
        return vec_bytes(positions) - before;
    }
    let key = key.to_owned();
    let positions = vec![pos];
    let added = key.capacity() as u64 + vec_bytes(&positions);
    index.insert(key, positions);
    added
}

#[cfg(test)]
pub(crate) fn index_walk_bytes(index: &RowIndex) -> u64 {
    table_bytes::<String, Vec<u32>>(index.capacity()) + index.iter().map(|(k, v)| k.capacity() as u64 + vec_bytes(v)).sum::<u64>()
}

/// Rows at or below the committed safe block, in chain-local order.
#[derive(Default)]
pub(crate) struct CommittedChain {
    pub(crate) deposits: Vec<DepositRow>,
    pub(crate) leaves: Vec<Hash>,
    pub(crate) by_address: RowIndex,
    pub(crate) by_tx: RowIndex,
    pub(crate) upper: UpperLevels,
    /// Capacity of every row string, index key and position list, kept as
    /// rows are appended.
    heap_bytes: u64,
}

impl CommittedChain {
    pub(crate) fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Appends rows in chain-local order: rows, then indexes, then leaves,
    /// then the complete subtrees the new leaves finish.
    pub(crate) fn append(&mut self, rows: &[DepositWithLeaf]) {
        let from_len = self.len();
        for (k, r) in rows.iter().enumerate() {
            let row = r.row.clone();
            let pos = position(from_len + k as u64);
            self.heap_bytes += deposit_heap_bytes(&row)
                + index_push(&mut self.by_address, &row.shield_address, pos)
                + index_push(&mut self.by_tx, &row.tx_hash, pos);
            self.deposits.push(row);
        }
        self.leaves.extend(rows.iter().map(|r| r.leaf));
        let to_len = self.len();
        let nodes = completed_nodes(&Tree::committed(self, to_len), from_len, to_len);
        self.upper.append(&nodes);
    }

    pub(crate) fn resident_bytes(&self) -> u64 {
        self.heap_bytes
            + vec_bytes(&self.deposits)
            + vec_bytes(&self.leaves)
            + self.upper.resident_bytes()
            + table_bytes::<String, Vec<u32>>(self.by_address.capacity())
            + table_bytes::<String, Vec<u32>>(self.by_tx.capacity())
    }

    #[cfg(test)]
    pub(crate) fn walk_bytes(&self) -> u64 {
        vec_bytes(&self.deposits)
            + self.deposits.iter().map(deposit_heap_bytes).sum::<u64>()
            + vec_bytes(&self.leaves)
            + self.upper.resident_bytes()
            + index_walk_bytes(&self.by_address)
            + index_walk_bytes(&self.by_tx)
    }
}

fn position(i: u64) -> u32 {
    u32::try_from(i).expect("a chain index holds at most 2^32 deposits")
}

/// The committed part of one chain index, shared by every view of it.
#[derive(Default)]
pub(crate) struct ChainData {
    pub(crate) committed: RwLock<CommittedChain>,
}

/// The rows above a committed boundary, rebuilt each tick and never changed.
/// Positions in its indexes are relative to the boundary.
#[derive(Default)]
pub(crate) struct WindowChain {
    pub(crate) deposits: Vec<DepositRow>,
    pub(crate) leaves: Vec<Hash>,
    pub(crate) by_address: RowIndex,
    pub(crate) by_tx: RowIndex,
    /// `completed_nodes(committed_len, committed_len + len)`: every complete
    /// subtree at the block level or above that ends inside the window.
    pub(crate) nodes: HashMap<(u8, u64), Hash>,
    /// Bytes of everything above, computed once by `build`.
    pub(crate) resident_bytes: u64,
}

impl WindowChain {
    /// The window of `rows` above the first `committed.len()` committed rows.
    pub(crate) fn build(committed: &CommittedChain, rows: &[DepositWithLeaf]) -> WindowChain {
        let mut w = WindowChain::default();
        let mut heap_bytes = 0;
        for (k, r) in rows.iter().enumerate() {
            let row = r.row.clone();
            let pos = position(k as u64);
            heap_bytes += deposit_heap_bytes(&row)
                + index_push(&mut w.by_address, &row.shield_address, pos)
                + index_push(&mut w.by_tx, &row.tx_hash, pos);
            w.deposits.push(row);
        }
        w.leaves.extend(rows.iter().map(|r| r.leaf));
        let committed_len = committed.len();
        let src = Tree { committed, committed_len, window_leaves: &w.leaves, window_nodes: None };
        let nodes = completed_nodes(&src, committed_len, src.len());
        w.nodes = nodes.into_iter().map(|(level, index, hash)| ((level, index), hash)).collect();
        w.resident_bytes = heap_bytes
            + vec_bytes(&w.deposits)
            + vec_bytes(&w.leaves)
            + table_bytes::<(u8, u64), Hash>(w.nodes.capacity())
            + table_bytes::<String, Vec<u32>>(w.by_address.capacity())
            + table_bytes::<String, Vec<u32>>(w.by_tx.capacity());
        w
    }

    #[cfg(test)]
    pub(crate) fn walk_bytes(&self) -> u64 {
        vec_bytes(&self.deposits)
            + self.deposits.iter().map(deposit_heap_bytes).sum::<u64>()
            + vec_bytes(&self.leaves)
            + table_bytes::<(u8, u64), Hash>(self.nodes.capacity())
            + index_walk_bytes(&self.by_address)
            + index_walk_bytes(&self.by_tx)
    }

    pub(crate) fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Whether this window holds exactly `rows`, by content.
    pub(crate) fn holds(&self, rows: &[DepositWithLeaf]) -> bool {
        self.deposits.len() == rows.len()
            && self.deposits.iter().zip(&self.leaves).zip(rows).all(|((d, l), r)| *d == r.row && *l == r.leaf)
    }
}

/// The tree a view sees: the first `committed_len` committed leaves, then the
/// window's. A complete subtree that ends above `committed_len` comes from the
/// window's own nodes, never from the committed store: the store only grows,
/// and after a reorg its nodes there belong to a newer branch.
pub(crate) struct Tree<'a> {
    committed: &'a CommittedChain,
    committed_len: u64,
    window_leaves: &'a [Hash],
    window_nodes: Option<&'a HashMap<(u8, u64), Hash>>,
}

impl<'a> Tree<'a> {
    fn committed(committed: &'a CommittedChain, committed_len: u64) -> Self {
        Tree { committed, committed_len, window_leaves: &[], window_nodes: None }
    }
}

impl TreeSource for Tree<'_> {
    fn len(&self) -> u64 {
        self.committed_len + self.window_leaves.len() as u64
    }

    fn leaf(&self, i: u64) -> Hash {
        if i < self.committed_len {
            self.committed.leaves[i as usize]
        } else {
            self.window_leaves[(i - self.committed_len) as usize]
        }
    }

    fn stored(&self, level: u8, index: u64) -> Option<Hash> {
        if (index + 1) << level <= self.committed_len {
            self.committed.upper.get(level, index)
        } else {
            self.window_nodes?.get(&(level, index)).copied()
        }
    }
}

/// One chain index as one published `View` sees it.
#[derive(Clone)]
pub struct ChainView {
    pub(crate) data: Arc<ChainData>,
    pub(crate) committed_len: u64,
    pub(crate) window: Arc<WindowChain>,
    /// `Err(reason)` while the chain is not ready.
    pub(crate) ready: Result<(), String>,
    pub(crate) meta: Option<TreeMetaRow>,
    /// The chain_id of every row on this chain index (C8); `None` before the
    /// first row.
    pub(crate) chain_id: Option<u64>,
    /// Root at `total()`.
    pub(crate) tree_root: Hash,
    pub(crate) last_verified_unix_ms: u64,
}

impl ChainView {
    /// A view of `data` that sees none of its rows, not ready for `reason`.
    pub(crate) fn not_ready(data: Arc<ChainData>, chain_id: Option<u64>, reason: String) -> ChainView {
        ChainView {
            data,
            committed_len: 0,
            window: Arc::new(WindowChain::default()),
            ready: Err(reason),
            meta: None,
            chain_id,
            tree_root: zero(32),
            last_verified_unix_ms: 0,
        }
    }

    pub(crate) fn total(&self) -> u64 {
        self.committed_len + self.window.len()
    }

    /// Takes the committed read lock once; everything read through the result
    /// comes from this view.
    pub(crate) fn read(&self) -> ChainRead<'_> {
        ChainRead { committed: self.data.committed.read(), view: self }
    }
}

/// The positions (chain-local indexes) of one key's rows in a view, in order.
pub(crate) struct Positions<'a> {
    committed: &'a [u32],
    window: &'a [u32],
    window_base: u64,
}

impl Positions<'_> {
    pub(crate) fn len(&self) -> usize {
        self.committed.len() + self.window.len()
    }

    pub(crate) fn get(&self, k: usize) -> u64 {
        match self.committed.get(k) {
            Some(p) => u64::from(*p),
            None => self.window_base + u64::from(self.window[k - self.committed.len()]),
        }
    }
}

/// A view of one chain index under one hold of its committed read lock.
pub(crate) struct ChainRead<'a> {
    committed: RwLockReadGuard<'a, CommittedChain>,
    view: &'a ChainView,
}

impl ChainRead<'_> {
    pub(crate) fn len(&self) -> u64 {
        self.view.total()
    }

    /// Row `i`; requires `i < len()`.
    pub(crate) fn row(&self, i: u64) -> &DepositRow {
        let cl = self.view.committed_len;
        if i < cl { &self.committed.deposits[i as usize] } else { &self.view.window.deposits[(i - cl) as usize] }
    }

    pub(crate) fn address(&self, shield_address: &str) -> Positions<'_> {
        self.positions(&self.committed.by_address, &self.view.window.by_address, shield_address)
    }

    pub(crate) fn tx(&self, tx_hash: &str) -> Positions<'_> {
        self.positions(&self.committed.by_tx, &self.view.window.by_tx, tx_hash)
    }

    fn positions<'b>(&'b self, committed: &'b RowIndex, window: &'b RowIndex, key: &str) -> Positions<'b> {
        let cl = self.view.committed_len;
        let committed = committed.get(key).map_or(&[][..], |v| &v[..v.partition_point(|p| u64::from(*p) < cl)]);
        let window = window.get(key).map_or(&[][..], Vec::as_slice);
        Positions { committed, window, window_base: cl }
    }

    /// Number of rows with `deposit_index < target` (deposit_index strictly
    /// increases along the chain).
    pub(crate) fn count_below(&self, target: u64) -> u64 {
        let cl = self.view.committed_len as usize;
        let committed = &self.committed.deposits[..cl];
        let below = committed.partition_point(|d| d.deposit_index < target);
        if below < cl {
            return below as u64;
        }
        (cl + self.view.window.deposits.partition_point(|d| d.deposit_index < target)) as u64
    }

    /// Chain-local position of the row with this `deposit_index`.
    pub(crate) fn find_deposit_index(&self, deposit_index: u64) -> Option<u64> {
        let below = self.count_below(deposit_index);
        (below < self.len() && self.row(below).deposit_index == deposit_index).then_some(below)
    }

    pub(crate) fn tree(&self) -> Tree<'_> {
        Tree {
            committed: &self.committed,
            committed_len: self.view.committed_len,
            window_leaves: &self.view.window.leaves,
            window_nodes: Some(&self.view.window.nodes),
        }
    }
}
