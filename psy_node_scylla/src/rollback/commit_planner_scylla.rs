//! Enumerates every physical row a Coordinator commit will write.
//!
//! Stateless on purpose: planning needs the fast-serialized layouts and the typed
//! key mappers, not any table handle or session.  That keeps it callable before
//! the hot writes, which is what design-r1 §3 requires so the manifest reaches
//! disk first.
//!
//! The order below follows `commit_state`'s own write order.  Order does not
//! affect correctness -- the manifest is a set -- but keeping them aligned makes
//! the two readable side by side, which is the only practical way to notice that
//! a newly added write has no matching plan step.
//!
//! Coverage is by construction rather than by convention: every step resolves
//! through a mapper from `mutation_sink`, and `locator_support` is an exhaustive
//! match over all 35 physical tables, so a table cannot be silently absent.

use parth_core::data::hash::merkle_node_key::PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE_KEY;
use psy_data::v1::qdata::ffs_sizes::{
    PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF, PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY,
};
use psy_node_core::store::{
    commit_planner::{
        CommitPlanError, CoordinatorCommitPlanInputs, CoordinatorCommitPlanner,
        PhysicalMutationSink, PlannedLocatorArtifact, checkpoint_tree_path_positions,
    },
    typed::CheckpointId,
};
use sha2::{Digest, Sha256};

use super::{
    CommitMutationSink, MutationLocatorRecord, RecordedOperation, ScyllaPhysicalTableId,
    encode_locator_chunks,
    describe_existing_key, key_id_value_key, public_key_to_user_key, realm_reward_node_key,
    record_bidirectional_pair_put, u64_mapping_key, u64_singleton_key, versioned_object_key,
    zero_merkle_node_key,
};

/// Bridges the driver-independent sink to the typed one.
///
/// `commit_state` holds only `PhysicalMutationSink`, while the mappers produce
/// `MutationLocatorRecord`.  This adapter keeps the validation in the typed
/// record while letting the caller stay driver-free.
struct SinkBridge<'a> {
    inner: &'a dyn PhysicalMutationSink,
}

impl CommitMutationSink for SinkBridge<'_> {
    fn record(&self, record: MutationLocatorRecord) {
        // The inner sink can fail, but `CommitMutationSink::record` cannot report
        // it.  Collecting sinks never fail; a failing one would be a programming
        // error rather than a runtime condition, so it is loud rather than lost.
        self.inner
            .record_physical_put(
                record.physical_table() as u16,
                record.locator_bytes().to_vec(),
            )
            .expect("physical mutation sink must accept every planned row");
    }
}

/// Stateless Coordinator commit planner.
pub struct ScyllaCoordinatorCommitPlanner;

impl ScyllaCoordinatorCommitPlanner {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ScyllaCoordinatorCommitPlanner {
    fn default() -> Self {
        Self::new()
    }
}

fn record_one(
    sink: &dyn PhysicalMutationSink,
    resolved: &super::ResolvedScyllaKey,
) -> anyhow::Result<()> {
    sink.record_physical_put(
        resolved.physical_table() as u16,
        resolved.locator_bytes().to_vec(),
    )
}

/// Plan a zero-id Merkle blob.
fn plan_zero_merkle_blob(
    sink: &dyn PhysicalMutationSink,
    physical: ScyllaPhysicalTableId,
    checkpoint: CheckpointId,
    field: &'static str,
    data: &[u8],
) -> anyhow::Result<()> {
    const NODE_LEN: usize = 41; // level(1) + index(8) + value(32)
    if data.len() % NODE_LEN != 0 {
        return Err(CommitPlanError::MalformedBlob {
            field,
            len: data.len(),
        }
        .into());
    }
    for chunk in data.chunks(NODE_LEN) {
        let level = chunk[0];
        let index = u64::from_le_bytes(chunk[1..9].try_into().expect("checked length"));
        let key = zero_merkle_node_key(physical, level, index, checkpoint)?;
        record_one(sink, &describe_existing_key(&key))?;
    }
    Ok(())
}

/// Plan a single-id Merkle blob.
fn plan_single_merkle_blob(
    sink: &dyn PhysicalMutationSink,
    physical: ScyllaPhysicalTableId,
    checkpoint: CheckpointId,
    field: &'static str,
    data: &[u8],
) -> anyhow::Result<()> {
    const NODE_LEN: usize = 49; // tree_id(8) + level(1) + index(8) + value(32)
    if data.len() % NODE_LEN != 0 {
        return Err(CommitPlanError::MalformedBlob {
            field,
            len: data.len(),
        }
        .into());
    }
    for chunk in data.chunks(NODE_LEN) {
        let tree_id = u64::from_le_bytes(chunk[0..8].try_into().expect("checked length"));
        let level = chunk[8];
        let index = u64::from_le_bytes(chunk[9..17].try_into().expect("checked length"));
        let key = super::single_merkle_node_key(physical, tree_id, level, index, checkpoint)?;
        record_one(sink, &describe_existing_key(&key))?;
    }
    Ok(())
}

/// Plan a versioned-object blob whose id sits in the first eight bytes.
fn plan_object_blob_id_at_start(
    sink: &dyn PhysicalMutationSink,
    physical: ScyllaPhysicalTableId,
    checkpoint: CheckpointId,
    object_size_without_id: usize,
    field: &'static str,
    data: &[u8],
) -> anyhow::Result<()> {
    let row_len = object_size_without_id + 8;
    if data.len() % row_len != 0 {
        return Err(CommitPlanError::MalformedBlob {
            field,
            len: data.len(),
        }
        .into());
    }
    for chunk in data.chunks(row_len) {
        let obj_id = u64::from_le_bytes(chunk[0..8].try_into().expect("checked length"));
        let key = versioned_object_key(physical, obj_id, checkpoint)?;
        record_one(sink, &describe_existing_key(&key))?;
    }
    Ok(())
}

impl CoordinatorCommitPlanner for ScyllaCoordinatorCommitPlanner {
    fn plan_coordinator_commit(
        &self,
        inputs: &CoordinatorCommitPlanInputs<'_>,
        sink: &dyn PhysicalMutationSink,
    ) -> anyhow::Result<()> {
        let checkpoint = CheckpointId::try_new(inputs.checkpoint_id)?;
        let kiv = |physical: ScyllaPhysicalTableId, obj_id: u64| -> anyhow::Result<()> {
            record_one(sink, &describe_existing_key(&key_id_value_key(physical, obj_id)?))
        };

        // 1. The ZK proof, written first by commit_state so recovery can find it.
        kiv(
            ScyllaPhysicalTableId::CheckpointZkProofAndTransition,
            inputs.checkpoint_id,
        )?;

        // 2. Both pending mappings.  Two separate logical tables, not a pair.
        record_one(
            sink,
            &describe_existing_key(&u64_mapping_key(
                ScyllaPhysicalTableId::PendingIdToCheckpointId,
                inputs.unique_pending_id,
            )?),
        )?;
        record_one(
            sink,
            &describe_existing_key(&u64_mapping_key(
                ScyllaPhysicalTableId::CheckpointIdToPendingId,
                inputs.checkpoint_id,
            )?),
        )?;

        // 3. Contract state.
        plan_object_blob_id_at_start(
            sink,
            ScyllaPhysicalTableId::ContractLeaf,
            checkpoint,
            PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF,
            "new_contract_leaves_ffs",
            inputs.new_contract_leaves_ffs,
        )?;
        // Code definitions and tree heights are written as typed rows rather than
        // a blob, and both occupy the same derived ids.
        for offset in 0..inputs.new_contract_code_definition_count as u64 {
            let contract_id = inputs.next_contract_id + offset;
            record_one(
                sink,
                &describe_existing_key(&versioned_object_key(
                    ScyllaPhysicalTableId::ContractCodeDefinition,
                    contract_id,
                    checkpoint,
                )?),
            )?;
            record_one(
                sink,
                &describe_existing_key(&versioned_object_key(
                    ScyllaPhysicalTableId::ContractStateTreeHeight,
                    contract_id,
                    checkpoint,
                )?),
            )?;
        }
        plan_single_merkle_blob(
            sink,
            ScyllaPhysicalTableId::ContractFunctionTree,
            checkpoint,
            "update_contract_function_tree_nodes_ffs",
            inputs.update_contract_function_tree_nodes_ffs,
        )?;
        plan_zero_merkle_blob(
            sink,
            ScyllaPhysicalTableId::GlobalContractTree,
            checkpoint,
            "update_global_contract_tree_nodes_ffs",
            inputs.update_global_contract_tree_nodes_ffs,
        )?;

        // 4. User registration.
        plan_object_blob_id_at_start(
            sink,
            ScyllaPhysicalTableId::UserPublicKey,
            checkpoint,
            PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY,
            "new_user_public_keys_ffs",
            inputs.new_user_public_keys_ffs,
        )?;
        plan_public_key_pairs(sink, inputs.new_public_key_hash_to_user_id_rows_ffs)?;
        plan_zero_merkle_blob(
            sink,
            ScyllaPhysicalTableId::UserRegistrationTree,
            checkpoint,
            "update_user_registration_tree_nodes_ffs",
            inputs.update_user_registration_tree_nodes_ffs,
        )?;

        // 5. Global user tree.
        plan_zero_merkle_blob(
            sink,
            ScyllaPhysicalTableId::GlobalUserTree,
            checkpoint,
            "update_global_user_tree_nodes_ffs",
            inputs.update_global_user_tree_nodes_ffs,
        )?;

        // 6. Realm reward node keys, clustered by pending rather than checkpoint.
        plan_reward_node_keys(
            sink,
            inputs.unique_pending_id,
            inputs.new_realm_guta_reward_tree_node_keys_ffs,
        )?;

        // 7. Checkpoint facts.
        kiv(
            ScyllaPhysicalTableId::CheckpointStateRoots,
            inputs.checkpoint_id,
        )?;
        kiv(ScyllaPhysicalTableId::L2BlockState, inputs.checkpoint_id)?;
        // latest_info slot 1 and the u64 singleton are overwritten in place; they
        // carry a before image in the manifest rather than a deletable version.
        kiv(ScyllaPhysicalTableId::LatestInfo, 1)?;
        record_one(sink, &describe_existing_key(&u64_singleton_key()))?;
        kiv(ScyllaPhysicalTableId::CheckpointLeaf, inputs.checkpoint_id)?;

        // 8. The checkpoint tree leaf and every ancestor above it.  Positions are
        // determined by height and index even though values are not, so the whole
        // path is planned rather than narrowed to the nodes that changed.
        for (level, index) in
            checkpoint_tree_path_positions(inputs.checkpoint_tree_height, inputs.checkpoint_id)
        {
            let key = zero_merkle_node_key(
                ScyllaPhysicalTableId::GlobalCheckpointTree,
                level,
                index,
                checkpoint,
            )?;
            record_one(sink, &describe_existing_key(&key))?;
        }

        // 9. Both halves of the checkpoint-root mapping.  The content-keyed row is
        // the one a rollback must delete; the height-keyed row is overwritten by
        // the new branch.
        let bridge = SinkBridge { inner: sink };
        record_bidirectional_pair_put(
            &bridge,
            ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1,
            inputs.checkpoint_root_bytes.to_vec(),
            inputs.checkpoint_id,
        )?;
        Ok(())
    }

    fn encode_planned_locators(
        &self,
        rows: Vec<(u16, Vec<u8>)>,
    ) -> anyhow::Result<PlannedLocatorArtifact> {
        Self::encode_locators(rows)
    }
}

fn plan_public_key_pairs(
    sink: &dyn PhysicalMutationSink,
    data: &[u8],
) -> anyhow::Result<()> {
    const PAIR_LEN: usize = 40;
    if data.len() % PAIR_LEN != 0 {
        return Err(CommitPlanError::MalformedBlob {
            field: "new_public_key_hash_to_user_id_rows_ffs",
            len: data.len(),
        }
        .into());
    }
    for chunk in data.chunks(PAIR_LEN) {
        let user = u64::from_le_bytes(chunk[32..40].try_into().expect("checked length"));
        let key = public_key_to_user_key(chunk[..32].to_vec(), user);
        record_one(sink, &describe_existing_key(&key))?;
    }
    Ok(())
}

fn plan_reward_node_keys(
    sink: &dyn PhysicalMutationSink,
    unique_pending_id: u64,
    data: &[u8],
) -> anyhow::Result<()> {
    let row_len = PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE_KEY + 8;
    if data.len() % row_len != 0 {
        return Err(CommitPlanError::MalformedBlob {
            field: "new_realm_guta_reward_tree_node_keys_ffs",
            len: data.len(),
        }
        .into());
    }
    for chunk in data.chunks(row_len) {
        let realm_id = u64::from_le_bytes(chunk[0..8].try_into().expect("checked length"));
        let key = realm_reward_node_key(realm_id, unique_pending_id)?;
        record_one(sink, &describe_existing_key(&key))?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use psy_node_core::store::commit_planner::CollectingPhysicalMutationSink;
    use std::collections::BTreeSet;

    pub(super) fn empty_inputs() -> CoordinatorCommitPlanInputs<'static> {
        CoordinatorCommitPlanInputs {
            checkpoint_id: 1001,
            unique_pending_id: 55,
            next_contract_id: 0,
            new_contract_code_definition_count: 0,
            update_global_contract_tree_nodes_ffs: &[],
            update_contract_function_tree_nodes_ffs: &[],
            new_contract_leaves_ffs: &[],
            update_user_registration_tree_nodes_ffs: &[],
            new_user_public_keys_ffs: &[],
            new_public_key_hash_to_user_id_rows_ffs: &[],
            update_global_user_tree_nodes_ffs: &[],
            new_realm_guta_reward_tree_node_keys_ffs: &[],
            checkpoint_root_bytes: &[7u8; 32],
            checkpoint_tree_height: 32,
        }
    }

    /// Plan into the production sink, then validate every row back into a typed
    /// record.  Validating on the way back is what the manifest builder does, so
    /// the tests exercise the same path.
    fn plan_records(
        inputs: &CoordinatorCommitPlanInputs<'_>,
    ) -> Vec<MutationLocatorRecord> {
        let sink = CollectingPhysicalMutationSink::new();
        ScyllaCoordinatorCommitPlanner::new()
            .plan_coordinator_commit(inputs, &sink)
            .unwrap();
        sink.take()
            .into_iter()
            .map(|(table_id, locator)| {
                MutationLocatorRecord::try_new(
                    ScyllaPhysicalTableId::try_from(table_id).expect("known table"),
                    RecordedOperation::Put,
                    locator,
                )
                .expect("planned locators must validate")
            })
            .collect()
    }

    fn planned_tables(inputs: &CoordinatorCommitPlanInputs<'_>) -> BTreeSet<ScyllaPhysicalTableId> {
        plan_records(inputs)
            .into_iter()
            .map(|record| record.physical_table())
            .collect()
    }

    #[test]
    fn an_empty_commit_still_plans_every_unconditional_table() {
        // These rows land on every commit regardless of what changed, so a
        // manifest that omitted them would under-record on the quietest blocks --
        // the ones least likely to be noticed.
        let tables = planned_tables(&empty_inputs());
        for expected in [
            ScyllaPhysicalTableId::CheckpointZkProofAndTransition,
            ScyllaPhysicalTableId::PendingIdToCheckpointId,
            ScyllaPhysicalTableId::CheckpointIdToPendingId,
            ScyllaPhysicalTableId::CheckpointStateRoots,
            ScyllaPhysicalTableId::L2BlockState,
            ScyllaPhysicalTableId::LatestInfo,
            ScyllaPhysicalTableId::U64Singleton,
            ScyllaPhysicalTableId::CheckpointLeaf,
            ScyllaPhysicalTableId::GlobalCheckpointTree,
            ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1,
            ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2,
        ] {
            assert!(tables.contains(&expected), "{expected:?} was not planned");
        }
    }

    #[test]
    fn the_checkpoint_tree_path_is_planned_in_full() {
        let inputs = empty_inputs();
        let tree_rows = plan_records(&inputs)
            .into_iter()
            .filter(|record| {
                record.physical_table() == ScyllaPhysicalTableId::GlobalCheckpointTree
            })
            .count();
        // Leaf plus every ancestor: over-recording here is a no-op delete, while
        // missing a level would leave a live node of the discarded branch.
        assert_eq!(tree_rows, inputs.checkpoint_tree_height as usize + 1);
    }

    #[test]
    fn a_full_commit_plans_every_table_the_commit_path_writes() {
        // 41-byte zero-id nodes, 49-byte single-id nodes, 40-byte key pairs,
        // 112-byte contract leaves, 72-byte public keys, 17-byte reward keys.
        let zero = [vec![0u8], 1u64.to_le_bytes().to_vec(), vec![9u8; 32]].concat();
        let single = [
            1u64.to_le_bytes().to_vec(),
            vec![0u8],
            2u64.to_le_bytes().to_vec(),
            vec![9u8; 32],
        ]
        .concat();
        let pair = [vec![3u8; 32], 6u64.to_le_bytes().to_vec()].concat();
        let leaf = [
            4u64.to_le_bytes().to_vec(),
            vec![0u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF],
        ]
        .concat();
        let public_key = [
            5u64.to_le_bytes().to_vec(),
            vec![0u8; PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY],
        ]
        .concat();
        let reward = [
            8u64.to_le_bytes().to_vec(),
            vec![0u8; PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE_KEY],
        ]
        .concat();
        let inputs = CoordinatorCommitPlanInputs {
            next_contract_id: 100,
            new_contract_code_definition_count: 2,
            update_global_contract_tree_nodes_ffs: &zero,
            update_contract_function_tree_nodes_ffs: &single,
            new_contract_leaves_ffs: &leaf,
            update_user_registration_tree_nodes_ffs: &zero,
            new_user_public_keys_ffs: &public_key,
            new_public_key_hash_to_user_id_rows_ffs: &pair,
            update_global_user_tree_nodes_ffs: &zero,
            new_realm_guta_reward_tree_node_keys_ffs: &reward,
            ..empty_inputs()
        };
        let tables = planned_tables(&inputs);
        // Exactly the twenty physical tables commit_state writes.
        let expected: BTreeSet<_> = [
            ScyllaPhysicalTableId::CheckpointZkProofAndTransition,
            ScyllaPhysicalTableId::PendingIdToCheckpointId,
            ScyllaPhysicalTableId::CheckpointIdToPendingId,
            ScyllaPhysicalTableId::ContractLeaf,
            ScyllaPhysicalTableId::ContractCodeDefinition,
            ScyllaPhysicalTableId::ContractStateTreeHeight,
            ScyllaPhysicalTableId::ContractFunctionTree,
            ScyllaPhysicalTableId::GlobalContractTree,
            ScyllaPhysicalTableId::UserPublicKey,
            ScyllaPhysicalTableId::PublicKeyHashToUserIds,
            ScyllaPhysicalTableId::UserRegistrationTree,
            ScyllaPhysicalTableId::GlobalUserTree,
            ScyllaPhysicalTableId::RealmRewardsTreeNodeKey,
            ScyllaPhysicalTableId::CheckpointStateRoots,
            ScyllaPhysicalTableId::L2BlockState,
            ScyllaPhysicalTableId::LatestInfo,
            ScyllaPhysicalTableId::U64Singleton,
            ScyllaPhysicalTableId::CheckpointLeaf,
            ScyllaPhysicalTableId::GlobalCheckpointTree,
            ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1,
            ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2,
        ]
        .into_iter()
        .collect();
        assert_eq!(tables, expected);
    }

    #[test]
    fn a_malformed_blob_names_the_field_and_records_nothing_further() {
        let mut broken = empty_inputs();
        let bad = vec![0u8; 40]; // not a multiple of 41
        broken.update_global_user_tree_nodes_ffs = &bad;
        let sink = CollectingPhysicalMutationSink::new();
        let error = ScyllaCoordinatorCommitPlanner::new()
            .plan_coordinator_commit(&broken, &sink)
            .unwrap_err();
        assert!(
            error.to_string().contains("update_global_user_tree_nodes_ffs"),
            "the error must name the field: {error}"
        );
    }

    #[test]
    fn every_planned_locator_is_distinct() {
        // A duplicate would make two rows look like one and shrink the delete
        // plan below what was archived.
        let records = plan_records(&empty_inputs());
        let distinct: BTreeSet<_> = records
            .iter()
            .map(|record| (record.physical_table(), record.locator_bytes().to_vec()))
            .collect();
        assert_eq!(distinct.len(), records.len(), "a locator was planned twice");
    }
}

const LOCATOR_SUMMARY_MAGIC: [u8; 8] = *b"PSYMSUM1";
const LOCATOR_SUMMARY_VERSION: u16 = 1;
const MUTATION_DIGEST_DOMAIN: &[u8] = b"psy.rollback.planned-mutation-set.v1\0";
const SUMMARY_DIGEST_DOMAIN: &[u8] = b"psy.rollback.locator-chunk.v1\0";

/// Canonical description of a chunk set: one digest per chunk, in order.
///
/// Small and fixed-width, so the manifest commits to the whole artifact set
/// without carrying it.  Order is part of the commitment, since chunk index is
/// how a gap is detected on read.
fn encode_locator_summary(chunks: &[Vec<u8>], affected_row_count: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 2 + 4 + 8 + chunks.len() * 32);
    out.extend_from_slice(&LOCATOR_SUMMARY_MAGIC);
    out.extend_from_slice(&LOCATOR_SUMMARY_VERSION.to_be_bytes());
    out.extend_from_slice(&(chunks.len() as u32).to_be_bytes());
    out.extend_from_slice(&affected_row_count.to_be_bytes());
    for chunk in chunks {
        let mut hasher = Sha256::new();
        hasher.update(SUMMARY_DIGEST_DOMAIN);
        hasher.update((chunk.len() as u64).to_be_bytes());
        hasher.update(chunk);
        out.extend_from_slice(&hasher.finalize());
    }
    out
}

impl ScyllaCoordinatorCommitPlanner {
    fn validate_planned_rows(
        rows: Vec<(u16, Vec<u8>)>,
    ) -> anyhow::Result<Vec<MutationLocatorRecord>> {
        rows.into_iter()
            .map(|(table_id, locator)| {
                MutationLocatorRecord::try_new(
                    ScyllaPhysicalTableId::try_from(table_id)?,
                    RecordedOperation::Put,
                    locator,
                )
                .map_err(anyhow::Error::from)
            })
            .collect()
    }
}

impl ScyllaCoordinatorCommitPlanner {
    /// Digest over the planned set, order-independent.
    ///
    /// A commit's rows are a set, and planning order is an implementation
    /// detail; making the digest depend on it would turn a harmless reordering
    /// into a false mismatch during recovery.
    fn mutation_digest(records: &[MutationLocatorRecord]) -> [u8; 32] {
        let mut leaves: Vec<[u8; 32]> = records
            .iter()
            .map(|record| {
                let mut hasher = Sha256::new();
                hasher.update((record.physical_table() as u16).to_be_bytes());
                hasher.update((record.locator_bytes().len() as u32).to_be_bytes());
                hasher.update(record.locator_bytes());
                hasher.finalize().into()
            })
            .collect();
        leaves.sort_unstable();
        let mut hasher = Sha256::new();
        hasher.update(MUTATION_DIGEST_DOMAIN);
        hasher.update((leaves.len() as u64).to_be_bytes());
        for leaf in leaves {
            hasher.update(leaf);
        }
        hasher.finalize().into()
    }
}

impl ScyllaCoordinatorCommitPlanner {
    /// The chunk codec both authorities share.
    ///
    /// `pub(crate)` rather than private because the Realm planner encodes with
    /// it too: one rollback planner decodes artifacts from either side, so a
    /// second encoder would be a second format to keep in step.
    pub(crate) fn encode_locators(rows: Vec<(u16, Vec<u8>)>) -> anyhow::Result<PlannedLocatorArtifact> {
        let records = Self::validate_planned_rows(rows)?;
        let affected_row_count = records.len() as u64;
        let mutation_digest = Self::mutation_digest(&records);
        let chunks = encode_locator_chunks(&records)?;
        let canonical_summary = encode_locator_summary(&chunks, affected_row_count);
        Ok(PlannedLocatorArtifact {
            chunks,
            mutation_digest,
            canonical_summary,
            affected_row_count,
        })
    }
}

#[cfg(test)]
mod encoding_tests {
    use super::*;
    use psy_node_core::store::commit_planner::CollectingPhysicalMutationSink;

    fn plan_artifact() -> PlannedLocatorArtifact {
        let sink = CollectingPhysicalMutationSink::new();
        let inputs = tests::empty_inputs();
        ScyllaCoordinatorCommitPlanner::new()
            .plan_coordinator_commit(&inputs, &sink)
            .unwrap();
        ScyllaCoordinatorCommitPlanner::new()
            .encode_planned_locators(sink.take())
            .unwrap()
    }

    #[test]
    fn the_summary_commits_to_every_chunk_and_the_row_count() {
        let artifact = plan_artifact();
        assert!(artifact.affected_row_count > 0);
        assert_eq!(artifact.chunk_count(), artifact.chunks.len() as u32);
        // magic + version + chunk count + row count + one digest per chunk
        assert_eq!(
            artifact.canonical_summary.len(),
            8 + 2 + 4 + 8 + artifact.chunks.len() * 32
        );
    }

    #[test]
    fn a_changed_chunk_changes_the_summary() {
        let artifact = plan_artifact();
        let mut tampered = artifact.chunks.clone();
        tampered[0][artifact.chunks[0].len() - 1] ^= 0xff;
        assert_ne!(
            encode_locator_summary(&tampered, artifact.affected_row_count),
            artifact.canonical_summary
        );
    }

    #[test]
    fn the_mutation_digest_ignores_planning_order() {
        // A commit's rows are a set.  Making the digest order-sensitive would
        // turn a harmless reordering of plan steps into a recovery mismatch.
        let sink = CollectingPhysicalMutationSink::new();
        let inputs = tests::empty_inputs();
        ScyllaCoordinatorCommitPlanner::new()
            .plan_coordinator_commit(&inputs, &sink)
            .unwrap();
        let mut rows = sink.take();
        let forward = ScyllaCoordinatorCommitPlanner::encode_locators(rows.clone()).unwrap();
        rows.reverse();
        let reversed = ScyllaCoordinatorCommitPlanner::encode_locators(rows).unwrap();
        assert_eq!(forward.mutation_digest, reversed.mutation_digest);
        assert_eq!(forward.affected_row_count, reversed.affected_row_count);
    }

    #[test]
    fn an_unresolvable_locator_is_refused_on_the_way_in() {
        assert!(
            ScyllaCoordinatorCommitPlanner::new()
                .encode_planned_locators(vec![(1u16, vec![0xff; 12])])
                .is_err()
        );
    }

    #[test]
    fn an_unknown_physical_table_is_refused() {
        assert!(
            ScyllaCoordinatorCommitPlanner::new()
                .encode_planned_locators(vec![(9999u16, vec![1u8; 12])])
                .is_err()
        );
    }
}
