//! What a Coordinator commit is about to write, in driver-independent terms.
//!
//! `commit_state` lives in `psy_node_common` and is generic over the store, so
//! it cannot name a Scylla type.  The planner is therefore a trait here, and its
//! inputs are primitives: every field below is reachable from
//! `PsyPreparedCoordinatorBlockStateUpdates` plus the two ids, which is what
//! makes one planner call enough to cover a whole commit instead of seventeen.
//!
//! ## Why over-recording is safe and under-recording is not
//!
//! A recorded locator names a row at this exact checkpoint.  If that row was
//! never written, rollback deletes nothing -- the row does not exist.  If a
//! written row was never recorded, rollback leaves it behind, and after the
//! height is reused it becomes a live row of the new branch carrying the
//! discarded branch's content.  Planners must therefore err towards recording
//! more, never less, and that is why the checkpoint-tree path is planned in full
//! rather than narrowed to the nodes that actually changed.

use std::error::Error;
use std::fmt;

/// Receives one physical row a commit will write.
///
/// Deliberately primitive: the table is a numeric physical id and the key is
/// already-canonical locator bytes, so this trait carries no storage types and
/// `psy_node_common` can hold it without depending on a driver.
pub trait PhysicalMutationSink: Send + Sync {
    fn record_physical_put(
        &self,
        physical_table_id: u16,
        locator_bytes: Vec<u8>,
    ) -> anyhow::Result<()>;
}

/// Everything needed to enumerate the rows one Coordinator commit will write.
///
/// Built by `commit_state` from the prepared update.  Blob fields are passed
/// through untouched: only the storage adapter knows how to decode them, which
/// is the whole reason the planner exists.
pub struct CoordinatorCommitPlanInputs<'a> {
    pub checkpoint_id: u64,
    pub unique_pending_id: u64,
    /// First contract id the new code definitions will occupy.  With the count
    /// below this yields the ids `set_many_contract_code_definitions` and
    /// `set_contract_tree_heights` write, which are derived rather than carried.
    pub next_contract_id: u64,
    pub new_contract_code_definition_count: usize,
    pub update_global_contract_tree_nodes_ffs: &'a [u8],
    pub update_contract_function_tree_nodes_ffs: &'a [u8],
    pub new_contract_leaves_ffs: &'a [u8],
    pub update_user_registration_tree_nodes_ffs: &'a [u8],
    pub new_user_public_keys_ffs: &'a [u8],
    pub new_public_key_hash_to_user_id_rows_ffs: &'a [u8],
    pub update_global_user_tree_nodes_ffs: &'a [u8],
    pub new_realm_guta_reward_tree_node_keys_ffs: &'a [u8],
    /// Canonical bytes of the new checkpoint root, for the content-keyed half of
    /// the bidirectional mapping.
    pub checkpoint_root_bytes: &'a [u8],
    /// Height of the global checkpoint tree, so the leaf and its ancestors can
    /// be enumerated by position.
    pub checkpoint_tree_height: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitPlanError {
    /// A blob field is not a whole number of rows.  Planning stops before
    /// recording anything: a partial plan would claim a row count the commit
    /// never writes.
    MalformedBlob { field: &'static str, len: usize },
    /// A table this commit writes has no locator mapper, so its rows would go
    /// unrecorded.  Failing closed keeps the manifest honest.
    UnmappedTable { field: &'static str },
}

impl fmt::Display for CommitPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedBlob { field, len } => {
                write!(f, "{field} is {len} bytes, not a whole number of rows")
            }
            Self::UnmappedTable { field } => {
                write!(f, "{field} writes a table with no locator mapper")
            }
        }
    }
}

impl Error for CommitPlanError {}

/// A planned mutation set, encoded and summarised.
///
/// The chunk codec belongs to the storage layer, so this carries its output
/// rather than its types.  `canonical_summary` is what the manifest commits to;
/// it must be the exact bytes the artifact-set commitment was built from, or the
/// PREPARED record will refuse to seal.
pub struct PlannedLocatorArtifact {
    pub chunks: Vec<Vec<u8>>,
    pub mutation_digest: [u8; 32],
    pub canonical_summary: Vec<u8>,
    pub affected_row_count: u64,
}

impl PlannedLocatorArtifact {
    pub fn chunk_count(&self) -> u32 {
        self.chunks.len() as u32
    }
}

/// Enumerates the physical rows one Coordinator commit will write.
///
/// Implemented by the storage layer, because only it can decode the blobs and
/// resolve typed keys.  Called before any hot write, so the manifest can reach
/// disk first (design-r1 §3).
pub trait CoordinatorCommitPlanner: Send + Sync {
    fn plan_coordinator_commit(
        &self,
        inputs: &CoordinatorCommitPlanInputs<'_>,
        sink: &dyn PhysicalMutationSink,
    ) -> anyhow::Result<()>;

    /// Validate the planned rows and encode them into canonical chunks.
    ///
    /// Validation happens here, on the way in, because a locator that cannot be
    /// resolved back to a key is useless to rollback and finding that out at
    /// delete time is far too late.
    fn encode_planned_locators(
        &self,
        rows: Vec<(u16, Vec<u8>)>,
    ) -> anyhow::Result<PlannedLocatorArtifact>;
}

/// Positions of a checkpoint-tree leaf and every ancestor above it.
///
/// Values depend on the current tree, but positions depend only on the height
/// and the leaf index, so the whole path is plannable.  Returned from the leaf
/// upwards, ending at the root.
pub fn checkpoint_tree_path_positions(height: u8, leaf_index: u64) -> Vec<(u8, u64)> {
    let mut out = Vec::with_capacity(height as usize + 1);
    let mut index = leaf_index;
    let mut level = height;
    loop {
        out.push((level, index));
        if level == 0 {
            break;
        }
        level -= 1;
        index >>= 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_runs_from_the_leaf_to_the_root() {
        let path = checkpoint_tree_path_positions(4, 13);
        assert_eq!(path, vec![(4, 13), (3, 6), (2, 3), (1, 1), (0, 0)]);
    }

    #[test]
    fn every_level_appears_exactly_once() {
        // A missing level would under-record, which is the unsafe direction.
        let height = 32u8;
        let path = checkpoint_tree_path_positions(height, 1_000_003);
        assert_eq!(path.len() as u8, height + 1);
        let levels: std::collections::BTreeSet<u8> = path.iter().map(|(l, _)| *l).collect();
        assert_eq!(levels.len() as u8, height + 1);
        assert_eq!(path.last(), Some(&(0, 0)));
    }

    #[test]
    fn a_zero_height_tree_is_a_single_node() {
        assert_eq!(checkpoint_tree_path_positions(0, 0), vec![(0, 0)]);
    }

    #[test]
    fn neighbouring_leaves_share_their_upper_levels_but_not_the_leaf() {
        let left = checkpoint_tree_path_positions(8, 10);
        let right = checkpoint_tree_path_positions(8, 11);
        assert_ne!(left[0], right[0]);
        assert_eq!(left[1..], right[1..]);
    }
}

/// Collects planned rows for one commit.
///
/// Lives here rather than beside the storage adapters because `commit_state`
/// builds it, and `commit_state` must not name a driver.  The rows come out as
/// primitives; turning them back into validated typed records is the storage
/// layer's job, and doing that on the way back means a malformed locator is
/// caught before it reaches a manifest.
#[derive(Default)]
pub struct CollectingPhysicalMutationSink {
    rows: std::sync::Mutex<Vec<(u16, Vec<u8>)>>,
}

impl CollectingPhysicalMutationSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Planned rows in plan order.
    pub fn take(&self) -> Vec<(u16, Vec<u8>)> {
        std::mem::take(&mut self.rows.lock().expect("sink mutex poisoned"))
    }

    pub fn len(&self) -> usize {
        self.rows.lock().expect("sink mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PhysicalMutationSink for CollectingPhysicalMutationSink {
    fn record_physical_put(
        &self,
        physical_table_id: u16,
        locator_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        if locator_bytes.is_empty() {
            anyhow::bail!("a planned row must carry a locator");
        }
        self.rows
            .lock()
            .expect("sink mutex poisoned")
            .push((physical_table_id, locator_bytes));
        Ok(())
    }
}
