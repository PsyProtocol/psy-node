//! Committed hashes of complete subtrees at level `BLOCK_LEVEL` and above.

use super::hash::Hash;
use super::snapshot::BLOCK_LEVEL;

/// Highest level stored: the root of the depth-32 tree.
const TOP_LEVEL: u8 = 32;

/// The append-only store of committed `(level, index) -> Hash` for levels
/// `BLOCK_LEVEL..=32`, one `Vec<Hash>` per level. Level `l` holds the complete
/// subtrees `0..len` in index order; a node is appended once, when the leaf
/// count first reaches its end.
#[derive(Debug, Clone, PartialEq)]
pub struct UpperLevels {
    levels: Vec<Vec<Hash>>,
}

impl UpperLevels {
    pub fn new() -> Self {
        Self { levels: vec![Vec::new(); usize::from(TOP_LEVEL - BLOCK_LEVEL) + 1] }
    }

    /// The stored node, or `None` for a level outside `BLOCK_LEVEL..=32` or an
    /// index not yet appended.
    pub fn get(&self, level: u8, index: u64) -> Option<Hash> {
        let nodes = self.level(level)?;
        nodes.get(usize::try_from(index).ok()?).copied()
    }

    /// Bytes of the level vectors at their allocated capacity.
    pub fn resident_bytes(&self) -> u64 {
        let nodes = self.levels.iter().map(|l| l.capacity() * std::mem::size_of::<Hash>()).sum::<usize>();
        (self.levels.capacity() * std::mem::size_of::<Vec<Hash>>() + nodes) as u64
    }

    /// Appends each node to its level. Panics unless every index equals that
    /// level's current length, so nodes can be neither skipped nor rewritten.
    /// The whole batch is checked first: a rejected batch appends nothing.
    pub fn append(&mut self, nodes: &[(u8, u64, Hash)]) {
        let mut lens = self.levels.iter().map(|l| l.len() as u64).collect::<Vec<_>>();
        for &(level, index, _) in nodes {
            assert!((BLOCK_LEVEL..=TOP_LEVEL).contains(&level), "level {level} is not stored");
            let len = &mut lens[usize::from(level - BLOCK_LEVEL)];
            assert_eq!(index, *len, "level {level} appends index {index} out of order");
            *len += 1;
        }
        for &(level, _, hash) in nodes {
            self.levels[usize::from(level - BLOCK_LEVEL)].push(hash);
        }
    }

    fn level(&self, level: u8) -> Option<&Vec<Hash>> {
        let offset = level.checked_sub(BLOCK_LEVEL)?;
        self.levels.get(usize::from(offset))
    }
}

impl Default for UpperLevels {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(v: u64) -> Hash {
        Hash::from_values(v, 0, 0, 0)
    }

    #[test]
    fn get_returns_only_appended_nodes() {
        let mut upper = UpperLevels::new();
        assert_eq!(upper.get(10, 0), None);
        upper.append(&[(10, 0, h(1)), (10, 1, h(2)), (11, 0, h(3)), (32, 0, h(4))]);
        assert_eq!(upper.get(10, 0), Some(h(1)));
        assert_eq!(upper.get(10, 1), Some(h(2)));
        assert_eq!(upper.get(11, 0), Some(h(3)));
        assert_eq!(upper.get(32, 0), Some(h(4)));
        assert_eq!(upper.get(10, 2), None);
        assert_eq!(upper.get(12, 0), None);
        assert_eq!(upper.get(9, 0), None);
        assert_eq!(upper.get(0, 0), None);
        assert_eq!(upper.get(33, 0), None);
        assert_eq!(upper.get(10, u64::MAX), None);
    }

    #[test]
    fn default_is_usable_like_new() {
        let mut upper = UpperLevels::default();
        assert_eq!(upper.get(10, 0), None);
        upper.append(&[(10, 0, h(1))]);
        assert_eq!(upper.get(10, 0), Some(h(1)));
    }

    #[test]
    #[should_panic(expected = "out of order")]
    fn append_rejects_a_skipped_index() {
        UpperLevels::new().append(&[(10, 1, h(1))]);
    }

    #[test]
    #[should_panic(expected = "out of order")]
    fn append_rejects_a_rewritten_index() {
        let mut upper = UpperLevels::new();
        upper.append(&[(10, 0, h(1))]);
        upper.append(&[(10, 0, h(2))]);
    }

    #[test]
    fn a_rejected_batch_appends_nothing() {
        let mut upper = UpperLevels::new();
        let batch = [(10, 0, h(1)), (11, 0, h(2)), (10, 2, h(3))];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| upper.append(&batch)));
        assert!(result.is_err());
        assert_eq!(upper, UpperLevels::new());
    }

    #[test]
    #[should_panic(expected = "is not stored")]
    fn append_rejects_a_level_below_the_block() {
        UpperLevels::new().append(&[(9, 0, h(1))]);
    }
}
