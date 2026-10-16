//! Detect distinct withdrawal leaves sharing the deployed Bridge's nonce key.
//!
//! A destination chain index routes to one configured Bridge. Different chains
//! have independent claimedNullifiers mappings; different users/tokens on the
//! same Bridge do not. Check before any claimed-flag read or proof generation.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, PartialEq, Eq)]
pub struct NonceConflict {
    pub destination_chain_index: u64,
    pub nonce: [u32; 8],
    /// Canonicalized leaf hashes; repeated observations of one leaf are harmless.
    pub leaf_hashes: Vec<String>,
}

impl NonceConflict {
    pub fn reason(&self) -> String {
        let nonce = self.nonce.iter().map(|word| format!("{word:08x}")).collect::<String>();
        format!(
            "withdrawal nonce conflict: destination_chain_index={}, nonce=0x{}, distinct_leaves={}; quarantined for manual reconciliation",
            self.destination_chain_index, nonce, self.leaf_hashes.len(),
        )
    }
}

/// Include pending AND retained retired leaves so a later scan/restart cannot
/// select a survivor of an already-known collision. Never choose a winner.
pub fn find_nonce_conflicts<'a>(
    withdrawals: impl IntoIterator<Item = (u64, [u32; 8], &'a str)>,
) -> Vec<NonceConflict> {
    let mut groups: BTreeMap<(u64, [u32; 8]), BTreeSet<String>> = BTreeMap::new();
    for (chain, nonce, leaf) in withdrawals {
        groups.entry((chain, nonce)).or_default().insert(leaf.to_ascii_lowercase());
    }
    groups.into_iter().filter_map(|((destination_chain_index, nonce), leaves)| {
        (leaves.len() > 1).then(|| NonceConflict {
            destination_chain_index,
            nonce,
            leaf_hashes: leaves.into_iter().collect(),
        })
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_leaves_with_one_nonce_are_all_conflicts() {
        let conflicts = find_nonce_conflicts([(0, [7; 8], "leaf-a"), (0, [7; 8], "leaf-b")]);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].leaf_hashes, ["leaf-a", "leaf-b"]);
    }

    #[test]
    fn observations_of_the_same_leaf_are_idempotent() {
        assert!(find_nonce_conflicts([(0, [7; 8], "0xABC"), (0, [7; 8], "0xabc")]).is_empty());
    }

    #[test]
    fn separate_destination_bridges_have_separate_nonce_namespaces() {
        assert!(find_nonce_conflicts([(0, [7; 8], "a"), (1, [7; 8], "b"), (2, [7; 8], "c")]).is_empty());
    }

    #[test]
    fn compares_all_eight_nonce_words() {
        let mut other = [7; 8];
        other[0] = 8;
        assert!(find_nonce_conflicts([(0, [7; 8], "a"), (0, other, "b")]).is_empty());
    }

    #[test]
    fn fourteen_leaf_incident_keeps_the_two_independent_leaves_out_of_conflict() {
        let mut rows = vec![(0, [0, 0, 0, 0, 0, 0, 0, 0x6acf9b89], "independent-a"),
                            (0, [0, 0, 0, 0, 0, 0, 0, 0x6acf9c3a], "independent-b")];
        let leaves = (0..12).map(|i| format!("collision-{i}")).collect::<Vec<_>>();
        rows.extend(leaves.iter().map(|leaf| (0, [0, 0, 0, 0, 0, 0, 0, 0x6acf9cd5], leaf.as_str())));
        let conflicts = find_nonce_conflicts(rows);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].leaf_hashes.len(), 12);
        assert!(conflicts[0].leaf_hashes.iter().all(|leaf| leaf.starts_with("collision-")));
    }

    #[test]
    fn a_later_pending_leaf_still_conflicts_with_a_retained_retired_leaf() {
        let retired = [(0, [7; 8], "retired")];
        let pending = [(0, [7; 8], "new")];
        let conflicts = find_nonce_conflicts(pending.into_iter().chain(retired));
        assert_eq!(conflicts[0].leaf_hashes, ["new", "retired"]);
    }
}
