//! Roots and claim proofs of the deposit tree at any indexed count.
//!
//! The tree at count `n` holds leaves `0..n` and zeros after them. A node at
//! `(level, i)` covers leaves `i << level .. (i + 1) << level`: it is
//! `zero(level)` when it starts at or after `n`, a leaf at level 0, the stored
//! hash when it is a complete subtree at `BLOCK_LEVEL` or above, and otherwise
//! the two-to-one hash of its children. A root or a proof therefore hashes at
//! most one partial block (under 1024 hashes) plus one node per level above
//! it, and a proof also hashes the leaf's own block.

use super::hash::{two_to_one, zero, Hash};

/// Complete subtrees at this level and above are stored; below it they are
/// hashed from the leaves. A block holds `1 << BLOCK_LEVEL` = 1024 leaves.
pub const BLOCK_LEVEL: u8 = 10;

/// Depth of the deposit tree: the root is at level 32.
const DEPTH: u8 = 32;

/// The indexed leaves of one chain index and the stored complete subtrees
/// over them. `len()` never exceeds `1 << 32`, the tree's capacity.
pub trait TreeSource {
    /// Number of indexed leaves.
    fn len(&self) -> u64;
    /// Leaf `i`; asked only for `i < len()`.
    fn leaf(&self, i: u64) -> Hash;
    /// The stored hash of the complete subtree `(level, index)`, or `None` if
    /// it is not stored. Asked only for `level >= BLOCK_LEVEL` and only for
    /// complete subtrees with `(index + 1) << level <= len()`.
    fn stored(&self, level: u8, index: u64) -> Option<Hash>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum TreeError {
    #[error("count {count} is above the {indexed} indexed leaves")]
    CountNotIndexed { count: u64, indexed: u64 },
    #[error("leaf {leaf} is not below count {count}")]
    LeafOutOfRange { leaf: u64, count: u64 },
    #[error("complete subtree ({level}, {index}) is not stored")]
    MissingStoredNode { level: u8, index: u64 },
}

/// A claim proof: the leaf, its 32 siblings from level 0 up, and the root they
/// fold to.
#[derive(Debug, Clone, PartialEq)]
pub struct Proof {
    pub leaf: Hash,
    pub siblings: Vec<Hash>,
    pub root: Hash,
}

/// Node `(level, i)` of the tree at count `n`. A complete subtree at
/// `BLOCK_LEVEL` or above comes only from `stored`: a missing one is an error,
/// never recomputed from the leaves.
fn value<S: TreeSource + ?Sized>(src: &S, level: u8, i: u64, n: u64) -> Result<Hash, TreeError> {
    let start = i << level;
    let end = (i + 1) << level;
    if start >= n {
        return Ok(zero(level));
    }
    if level == 0 {
        return Ok(src.leaf(i));
    }
    if end <= n && level >= BLOCK_LEVEL {
        return src.stored(level, i).ok_or(TreeError::MissingStoredNode { level, index: i });
    }
    Ok(two_to_one(value(src, level - 1, 2 * i, n)?, value(src, level - 1, 2 * i + 1, n)?))
}

fn check_count<S: TreeSource + ?Sized>(src: &S, n: u64) -> Result<(), TreeError> {
    let indexed = src.len();
    if n > indexed {
        return Err(TreeError::CountNotIndexed { count: n, indexed });
    }
    Ok(())
}

/// Root of the tree over the first `n` leaves; `zero(32)` when `n == 0`.
pub fn root_at(src: &impl TreeSource, n: u64) -> Result<Hash, TreeError> {
    check_count(src, n)?;
    value(src, DEPTH, 0, n)
}

/// Proof of `leaf` in the tree over the first `n` leaves. The root is the fold
/// of the leaf with its siblings, which equals `root_at(src, n)`.
pub fn proof_at(src: &impl TreeSource, leaf: u64, n: u64) -> Result<Proof, TreeError> {
    check_count(src, n)?;
    if leaf >= n {
        return Err(TreeError::LeafOutOfRange { leaf, count: n });
    }
    let siblings = (0..DEPTH).map(|level| value(src, level, (leaf >> level) ^ 1, n)).collect::<Result<Vec<_>, _>>()?;
    let leaf_hash = src.leaf(leaf);
    let root = siblings.iter().enumerate().fold(leaf_hash, |node, (level, sibling)| {
        if (leaf >> level) & 1 == 0 { two_to_one(node, *sibling) } else { two_to_one(*sibling, node) }
    });
    Ok(Proof { leaf: leaf_hash, siblings, root })
}

/// Every complete subtree at `BLOCK_LEVEL` or above that ends in
/// `(from_len, to_len]`, as `(level, index, hash)` in increasing level order
/// and increasing index within a level: what the store appends when the count
/// grows from `from_len` to `to_len`.
///
/// Requires `from_len <= to_len <= src.len()`, leaves `0..to_len`, and every
/// complete subtree at `BLOCK_LEVEL` or above that ends at or before
/// `from_len` stored. Panics if one of those stored nodes is missing: a node
/// above the block level is never recomputed from the leaves.
pub fn completed_nodes(src: &impl TreeSource, from_len: u64, to_len: u64) -> Vec<(u8, u64, Hash)> {
    assert!(from_len <= to_len, "completed_nodes range ({from_len}, {to_len}] is reversed");
    assert!(to_len <= src.len(), "completed_nodes to {to_len} is above the {} indexed leaves", src.len());
    assert!(to_len <= 1u64 << DEPTH, "completed_nodes to {to_len} is above the tree capacity");
    let mut out = Vec::new();
    // The nodes this call produced on the level below, from index `below_first`.
    let mut below: Vec<Hash> = Vec::new();
    let mut below_first = 0u64;
    for level in BLOCK_LEVEL..=DEPTH {
        // Node i ends at (i + 1) << level, which is in (from_len, to_len]
        // exactly when from_len >> level <= i < to_len >> level.
        let first = from_len >> level;
        let last = to_len >> level;
        if first >= last {
            // The right child of a new node is new too, so no level above has one.
            break;
        }
        let child = |j: u64| -> Hash {
            match j.checked_sub(below_first).and_then(|k| below.get(usize::try_from(k).ok()?)) {
                Some(h) => *h,
                None => src.stored(level - 1, j).unwrap_or_else(|| {
                    panic!("completed_nodes needs stored node ({}, {j}), which ends at or before {from_len}", level - 1)
                }),
            }
        };
        let current = (first..last)
            .map(|i| if level == BLOCK_LEVEL { block_hash(src, i) } else { two_to_one(child(2 * i), child(2 * i + 1)) })
            .collect::<Vec<_>>();
        out.extend(current.iter().enumerate().map(|(k, h)| (level, first + k as u64, *h)));
        below = current;
        below_first = first;
    }
    out
}

/// Hash of the complete block `i`, from its 1024 leaves.
fn block_hash<S: TreeSource + ?Sized>(src: &S, i: u64) -> Hash {
    let start = i << BLOCK_LEVEL;
    let mut layer = (start..start + (1 << BLOCK_LEVEL)).map(|j| src.leaf(j)).collect::<Vec<_>>();
    while layer.len() > 1 {
        layer = layer.chunks_exact(2).map(|pair| two_to_one(pair[0], pair[1])).collect();
    }
    layer[0]
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::test_support::{fixture, naive_root, naive_siblings};
    use crate::tree::hash::to_display_hex;
    use crate::tree::upper::UpperLevels;

    /// Leaves in memory and the stored nodes `completed_nodes` produced for them.
    struct VecSource {
        leaves: Vec<Hash>,
        upper: UpperLevels,
    }

    impl VecSource {
        fn leaves_only(leaves: Vec<Hash>) -> Self {
            Self { leaves, upper: UpperLevels::new() }
        }

        fn from_fixture() -> Self {
            let mut src = Self::leaves_only(fixture().leaves);
            let nodes = completed_nodes(&src, 0, src.len());
            src.upper.append(&nodes);
            src
        }
    }

    impl TreeSource for VecSource {
        fn len(&self) -> u64 {
            self.leaves.len() as u64
        }

        fn leaf(&self, i: u64) -> Hash {
            self.leaves[usize::try_from(i).unwrap()]
        }

        fn stored(&self, level: u8, index: u64) -> Option<Hash> {
            assert_stored_contract(level, index, self.len());
            self.upper.get(level, index)
        }
    }

    fn assert_stored_contract(level: u8, index: u64, len: u64) {
        assert!(level >= BLOCK_LEVEL, "stored asked below the block level: ({level}, {index})");
        assert!((index + 1) << level <= len, "stored asked for an incomplete subtree ({level}, {index}) at len {len}");
    }

    /// A source of `len` equal leaves, so a complete subtree at level `l` is
    /// `full[l]` wherever it sits and the stored nodes of any count are known
    /// without hashing the leaves. It counts the leaves and stored nodes read.
    struct FarSource {
        len: u64,
        full: Vec<Hash>,
        leaf_calls: Cell<u64>,
        stored_calls: Cell<u64>,
    }

    impl FarSource {
        fn new(len: u64) -> Self {
            let mut full = vec![Hash::from_values(7, 1, 0, 0)];
            for level in 0..32 {
                full.push(two_to_one(full[level], full[level]));
            }
            Self { len, full, leaf_calls: Cell::new(0), stored_calls: Cell::new(0) }
        }

        fn reset(&self) {
            self.leaf_calls.set(0);
            self.stored_calls.set(0);
        }
    }

    impl TreeSource for FarSource {
        fn len(&self) -> u64 {
            self.len
        }

        fn leaf(&self, i: u64) -> Hash {
            assert!(i < self.len, "leaf {i} read past len {}", self.len);
            self.leaf_calls.set(self.leaf_calls.get() + 1);
            // Fail fast instead of hashing billions of leaves.
            assert!(self.leaf_calls.get() <= 1 << 12, "more than 4096 leaves read");
            self.full[0]
        }

        fn stored(&self, level: u8, index: u64) -> Option<Hash> {
            assert_stored_contract(level, index, self.len);
            self.stored_calls.set(self.stored_calls.get() + 1);
            Some(self.full[usize::from(level)])
        }
    }

    fn fold(leaf: u64, leaf_hash: Hash, siblings: &[Hash]) -> Hash {
        siblings.iter().enumerate().fold(leaf_hash, |node, (level, sibling)| {
            if (leaf >> level) & 1 == 0 { two_to_one(node, *sibling) } else { two_to_one(*sibling, node) }
        })
    }

    #[test]
    fn root_at_every_count_matches_envio() {
        let src = VecSource::from_fixture();
        for (k, root) in fixture().roots_after.iter().enumerate() {
            assert_eq!(to_display_hex(&root_at(&src, k as u64 + 1).unwrap()), *root);
        }
    }

    #[test]
    fn proofs_match_the_reference_at_boundary_counts() {
        let src = VecSource::from_fixture();
        for n in [1u64, 2, 3, 1023, 1024, 1025, 2047, 2048, 2049, 2100] {
            for leaf in [0, 1, n / 2, n - 1].into_iter().filter(|l| *l < n) {
                let p = proof_at(&src, leaf, n).unwrap();
                assert_eq!(p.siblings, naive_siblings(&src.leaves, leaf, n));
                assert_eq!(p.root, naive_root(&src.leaves, n));
                assert_eq!(p.leaf, src.leaves[leaf as usize]);
            }
        }
    }

    #[test]
    fn root_above_indexed_count_is_an_error() {
        let src = VecSource::from_fixture();
        assert_eq!(root_at(&src, 2101), Err(TreeError::CountNotIndexed { count: 2101, indexed: 2100 }));
        assert_eq!(proof_at(&src, 5, 5).unwrap_err(), TreeError::LeafOutOfRange { leaf: 5, count: 5 });
    }

    #[test]
    fn completed_nodes_cover_each_block_once() {
        let src = VecSource::leaves_only(fixture().leaves);
        let nodes = completed_nodes(&src, 1000, 2100);
        assert_eq!(nodes.iter().filter(|(l, _, _)| *l == 10).map(|(_, i, _)| *i).collect::<Vec<_>>(), vec![0, 1]);
        assert_eq!(nodes.iter().filter(|(l, _, _)| *l == 11).count(), 1);
    }

    #[test]
    fn root_at_zero_is_the_empty_tree() {
        let src = VecSource::leaves_only(Vec::new());
        assert_eq!(root_at(&src, 0), Ok(zero(32)));
        assert_eq!(root_at(&src, 1), Err(TreeError::CountNotIndexed { count: 1, indexed: 0 }));
        assert_eq!(proof_at(&src, 0, 0).unwrap_err(), TreeError::LeafOutOfRange { leaf: 0, count: 0 });
    }

    #[test]
    fn proof_above_indexed_count_is_an_error() {
        let src = VecSource::from_fixture();
        assert_eq!(proof_at(&src, 0, 2101).unwrap_err(), TreeError::CountNotIndexed { count: 2101, indexed: 2100 });
    }

    #[test]
    fn a_missing_stored_node_is_an_error_not_a_recomputation() {
        let src = VecSource::leaves_only(fixture().leaves);
        // Below one block nothing stored is needed.
        assert_eq!(to_display_hex(&root_at(&src, 1023).unwrap()), fixture().roots_after[1022]);
        assert_eq!(root_at(&src, 1024), Err(TreeError::MissingStoredNode { level: 10, index: 0 }));
        assert_eq!(root_at(&src, 2100), Err(TreeError::MissingStoredNode { level: 11, index: 0 }));
        assert_eq!(proof_at(&src, 2099, 2100).unwrap_err(), TreeError::MissingStoredNode { level: 11, index: 0 });
        assert_eq!(proof_at(&src, 1050, 1100).unwrap_err(), TreeError::MissingStoredNode { level: 10, index: 0 });
        // Leaf 0 sits inside block 0, so its proof never asks for block 0 itself.
        assert_eq!(proof_at(&src, 0, 1100).unwrap().siblings, naive_siblings(&src.leaves, 0, 1100));
    }

    #[test]
    fn completed_nodes_one_deposit_at_a_time_equal_one_batch() {
        let leaves = fixture().leaves;
        let mut src = VecSource::leaves_only(Vec::new());
        for leaf in &leaves {
            let from_len = src.len();
            src.leaves.push(*leaf);
            let nodes = completed_nodes(&src, from_len, src.len());
            assert!(nodes.windows(2).all(|w| w[0].0 <= w[1].0), "levels out of order at {from_len}");
            src.upper.append(&nodes);
        }
        assert_eq!(src.upper, VecSource::from_fixture().upper);
        let batch = completed_nodes(&VecSource::leaves_only(leaves), 0, 2100);
        assert_eq!(batch.iter().map(|(l, i, _)| (*l, *i)).collect::<Vec<_>>(), vec![(10, 0), (10, 1), (11, 0)]);
    }

    #[test]
    fn completed_nodes_of_an_empty_range_is_empty() {
        let src = VecSource::from_fixture();
        assert!(completed_nodes(&src, 2100, 2100).is_empty());
        assert!(completed_nodes(&src, 1024, 2047).is_empty());
    }

    #[test]
    #[should_panic(expected = "completed_nodes needs stored node (10, 0)")]
    fn completed_nodes_refuse_to_recompute_a_missing_stored_node() {
        // Block 0 ended at 1024 but was never stored, and level 11 needs it.
        completed_nodes(&VecSource::leaves_only(fixture().leaves), 1024, 2048);
    }

    #[test]
    fn far_roots_and_proofs_read_stored_nodes_not_leaves() {
        // Three quarters of the tree plus five blocks: the leaves below the
        // last block boundary sit under stored nodes.
        let aligned = (3u64 << 30) + (5 << BLOCK_LEVEL);
        let src = FarSource::new(aligned);
        root_at(&src, aligned).unwrap();
        assert_eq!(src.leaf_calls.get(), 0);
        assert!(src.stored_calls.get() <= 32, "{} stored reads", src.stored_calls.get());

        let n = aligned + 7;
        let src = FarSource::new(n);
        let root = root_at(&src, n).unwrap();
        assert_eq!(src.leaf_calls.get(), 7);

        // A leaf in the partial last block: only that block's 7 leaves.
        src.reset();
        let p = proof_at(&src, n - 1, n).unwrap();
        assert_eq!(src.leaf_calls.get(), 7);
        assert_eq!(p.root, root);
        assert_eq!(fold(n - 1, p.leaf, &p.siblings), root);

        // A leaf in a complete block: its own block and the partial last one.
        src.reset();
        let p = proof_at(&src, 5, n).unwrap();
        assert_eq!(src.leaf_calls.get(), 1024 + 7);
        assert_eq!(p.root, root);
        assert_eq!(fold(5, p.leaf, &p.siblings), root);
    }

    #[test]
    fn root_and_proof_of_a_full_tree() {
        let full = 1u64 << 32;
        let src = FarSource::new(full);
        assert_eq!(root_at(&src, full), Ok(src.full[32]));
        assert_eq!(src.leaf_calls.get(), 0);
        let p = proof_at(&src, full - 1, full).unwrap();
        assert_eq!(p.root, src.full[32]);
        assert_eq!(p.siblings, src.full[..32].to_vec());
    }
}
