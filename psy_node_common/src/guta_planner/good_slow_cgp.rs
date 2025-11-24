use std::{collections::HashMap, sync::Arc};

use parth_common::memory_stores::{
    dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore,
    mem_tree_recorder::SimpleMemoryMerkleRecorderStore,
};
use parth_core::{
    crypto::hash::traits::{FieldQHasher, QFieldHashable},
    felt::QFelt64,
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    guta::{header::GlobalUserTreeAggregatorHeader, header_extended::{
        GlobalUserTreeAggregatorHeaderWithJobId,
        GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
    }},
    proof_input::guta::{
        GUTANoChangeFullInput,
        GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput,
        GUTAVerifyTwoGUTACircuitInputV2,
        GUTAVerifyTwoGUTALinearCircuitInput,
        GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2,
        VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple,
    },
    v1::qdata::checkpoint::{
        PQEDCheckpointGlobalStateRoots,
        PQEDCheckpointLeafCompact,
        PQEDCheckpointLeafCompactWithStateRoots,
        PQEDCheckpointLeafStats,
    },
    worker::{
        metadata::{
            PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD,
            PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
            PsyProvingJobMetadata,
        },
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    },
};
use psy_node_core::psy_temp_db::StandardProcessorTempDBStoreBase;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;


const MAX_COORDINATOR_HEIGHT: usize = 24;

/// Represents a node in the aggregation tree being built.
/// Can be an input leaf or an intermediate aggregation result.
#[derive(Clone)]
struct PlannerNode<F, Hash> {
    pub job_id: QProvingJobDataID,
    pub header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub node_type: PlannerNodeType,
}

#[derive(Clone, PartialEq, Debug)]
enum PlannerNodeType {
    /// A raw input proof from a realm (Level R of global tree)
    InputLeaf,
    /// A proof that has been promoted/aggregated to represent a Root transition (Level 0 of global tree)
    LinearAggregated,
}

pub struct CoordinatorGUTAPlanner<F, Hash> {
    /// Stores witnesses generated during finalization.
    pub job_witnesses: Vec<(QProvingJobDataID, Vec<u8>)>,
    /// The finalized schedule of jobs, organized by level.
    /// Level 0 = Promoters/First Aggregations, Level N = Root.
    /// Note: Logic differs from intern's 'Level 0 = Inputs'.
    /// Here, inputs are processed into the first level of jobs.
    pub job_levels: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>>>,
    /// Raw input jobs accumulated during streaming.
    input_buffer: Vec<GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash>>,
}

impl<F, Hash> CoordinatorGUTAPlanner<F, Hash> {
    pub fn new() -> Self {
        Self {
            job_witnesses: Vec::new(),
            job_levels: Vec::new(),
            input_buffer: Vec::new(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash + QFHashBase<F>> CoordinatorGUTAPlanner<F, Hash> {
    
    /// Adds a realm job to the buffer. Logic is deferred to finalize to optimize tree height.
    pub async fn add_realm_job<Hasher: FieldQHasher<F, Hash>, TempStore: StandardProcessorTempDBStoreBase<QProvingJobDataID, Hash>>(
        &mut self,
        _unique_pending_id: u64,
        _current_checkpoint_root: &Hash,
        _checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        _global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        _temp_store: Arc<TempStore>,
        job: &GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash>,
    ) -> anyhow::Result<()> {
        // We simply buffer inputs. The complex aggregation logic happens in finalize
        // to ensure we build a balanced tree with minimal height O(logN).
        let mut job = job.clone();
        self.input_buffer.push(job.clone());
        Ok(())
    }

    /// Core logic to aggregate two nodes into one parent node.
    /// Generates the witness, adds it to `job_witnesses`, and returns the new parent node.
    #[allow(clippy::too_many_arguments)]
    fn create_aggregate_job<Hasher: FieldQHasher<F, Hash>>(
        &mut self,
        left: PlannerNode<F, Hash>,
        right: PlannerNode<F, Hash>,
        unique_pending_id: u64,
        current_checkpoint_root: &Hash,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        level_idx: usize,
        item_idx: usize,
    ) -> anyhow::Result<PlannerNode<F, Hash>> {
        let left_is_leaf = left.node_type == PlannerNodeType::InputLeaf;
        let right_is_leaf = right.node_type == PlannerNodeType::InputLeaf;

        let left_cp = left.header.checkpoint_tree_root;
        let right_cp = right.header.checkpoint_tree_root;
        
        let left_needs_cp_upgrade = left_is_leaf && (&left_cp != current_checkpoint_root);
        let right_needs_cp_upgrade = right_is_leaf && (&right_cp != current_checkpoint_root);

        // Determine Circuit Type and Input Data
        let (witness_bytes, new_header, circuit_type) = if left_is_leaf && right_is_leaf {
            // Case: Two Input Leaves (GUTATwoGUTA or GUTATwoGUTAWithCheckpointUpgrade)
            
            let left_dmp = global_user_tree.set_leaf(
                left.header.state_transition.node_index.to_u64_value(),
                left.header.state_transition.new_node_value,
            );
            let right_dmp = global_user_tree.set_leaf(
                right.header.state_transition.node_index.to_u64_value(),
                right.header.state_transition.new_node_value,
            );

            if left_needs_cp_upgrade || right_needs_cp_upgrade {
                // Use Checkpoint Upgrade Circuit
                let input = GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2 {
                    left_header: left.header,
                    left_global_user_tree_delta_merkle_proof: left_dmp,
                    left_historical_checkpoint_merkle_proof: checkpoint_tree.get_historical_append_only_merkle_proof_for_root(left_cp)?,
                    right_header: right.header,
                    right_global_user_tree_delta_merkle_proof: right_dmp,
                    right_historical_checkpoint_merkle_proof: checkpoint_tree.get_historical_append_only_merkle_proof_for_root(right_cp)?,
                };
                (
                    input.psy_ser_to_bytes_vec()?,
                    input.get_new_guta_header(),
                    ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade,
                )
            } else {
                // Standard Circuit
                let input = GUTAVerifyTwoGUTACircuitInputV2 {
                    left_header: left.header,
                    left_global_user_tree_delta_merkle_proof: left_dmp,
                    right_header: right.header,
                    right_global_user_tree_delta_merkle_proof: right_dmp,
                };
                (
                    input.psy_ser_to_bytes_vec()?,
                    input.get_new_guta_header(),
                    ProvingJobCircuitType::GUTATwoGUTA,
                )
            }
        } else if !left_is_leaf && !right_is_leaf {
            // Case: Two Linear Aggregates (GUTATwoGUTALinear)
            let input = GUTAVerifyTwoGUTALinearCircuitInput {
                left_header: left.header,
                right_header: right.header,
            };
            (
                input.psy_ser_to_bytes_vec()?,
                input.get_new_guta_header(),
                ProvingJobCircuitType::GUTATwoGUTALinear,
            )
        } else if !left_is_leaf && right_is_leaf {
            // Case: Left Linear, Right Leaf (GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint)
            let right_dmp = global_user_tree.set_leaf(
                right.header.state_transition.node_index.to_u64_value(),
                right.header.state_transition.new_node_value,
            );
            
            let input = GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput {
                left_header: left.header,
                right_header: right.header,
                right_global_user_tree_delta_merkle_proof: right_dmp,
                right_historical_checkpoint_proof: checkpoint_tree.get_historical_append_only_merkle_proof_for_root(right_cp)?,
            };
            
            (
                input.psy_ser_to_bytes_vec()?,
                input.get_new_guta_header(),
                ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint,
            )
        } else {
            // Case: Left Leaf, Right Linear -> Should not happen with left-to-right processing
            anyhow::bail!("Invalid aggregation pair: Left=Leaf, Right=Linear. Planner logic error.");
        };

        let new_job_id = QProvingJobDataID::new_proof_job_id(
            unique_pending_id,
            level_idx as u32,
            circuit_type,
            0,
            item_idx as u32,
        );

        self.job_witnesses.push((new_job_id, witness_bytes));

        // Create metadata for the schedule
        let mut metadata = GlobalUserTreeAggregatorHeaderWithJobId{
            header: new_header.clone(),
            job_id: new_job_id,
        }.to_metadata_with_job_standard_children::<Hasher>(vec![left.job_id, right.job_id]);
        
        metadata.job_id = new_job_id;
        
        if self.job_levels.len() <= level_idx {
            self.job_levels.resize(level_idx + 1, Vec::new());
        }
        self.job_levels[level_idx].push(metadata);

        Ok(PlannerNode {
            job_id: new_job_id,
            header: new_header,
            node_type: PlannerNodeType::LinearAggregated,
        })
    }

    fn create_singlet_root_promotion_job<Hasher: FieldQHasher<F, Hash>>(
        &mut self,
        node: PlannerNode<F, Hash>,
        unique_pending_id: u64,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    ) -> anyhow::Result<PlannerNode<F, Hash>> {
        if node.node_type != PlannerNodeType::InputLeaf {
             anyhow::bail!("Cannot promote already linear node via ToCap circuit");
        }

        let dmp = global_user_tree.set_leaf(
            node.header.state_transition.node_index.to_u64_value(),
            node.header.state_transition.new_node_value,
        );

        let input = VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple {
            guta_proof_header: node.header,
            top_line_siblings: dmp.siblings,
            historical_checkpoint_proof: checkpoint_tree.get_historical_append_only_merkle_proof_for_root(node.header.checkpoint_tree_root)?,
            total_aggregation_proofs_generated: node.header.total_aggregation_proofs_generated,
        };

        let witness_bytes = input.psy_ser_to_bytes_vec()?;
        
        let new_job_id = QProvingJobDataID::new_proof_job_id(
            unique_pending_id,
            0,
            ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade,
            0,
            0,
        );

        self.job_witnesses.push((new_job_id, witness_bytes));

        let expected_hash = input.get_public_inputs_hash_no_rewards_tag::<Hasher>();
        
        let metadata = PsyProvingJobMetadataWithJobId {
            job_id: new_job_id,
            metadata: PsyProvingJobMetadata {
                expected_public_inputs_hash: expected_hash,
                reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD,
                reward_tree_node_index: 0, // set later
                reward_tree_node_level: 0, // set later
                reward_tree_node_children: 1,
                dependencies: vec![node.job_id],
            },
        };

        if self.job_levels.is_empty() {
            self.job_levels.push(Vec::new());
        }
        self.job_levels[0].push(metadata);

        Ok(node) 
    }

    /// Recursive function to set reward tree indices in the generated job graph.
    /// The reward index of a child is strictly derived from its position in the
    /// level vector (dep_index) relative to the parent's reward index.
    fn update_reward_tree_config(
        &mut self,
        job_id: &QProvingJobDataID,
        level: u8,
        index: u64,
    ) -> anyhow::Result<()> {
        let mut deps = Vec::new();

        // 1. Find the current job in job_levels and set its info
        let mut found_in_levels = false;
        for level_vec in self.job_levels.iter_mut() {
            for job in level_vec.iter_mut() {
                if &job.job_id == job_id {
                    job.metadata.reward_tree_node_level = level;
                    job.metadata.reward_tree_node_index = index;
                    deps = job.metadata.dependencies.clone();
                    found_in_levels = true;
                    break;
                }
            }
            if found_in_levels { break; }
        }

        // If not found in job_levels, it's an input leaf, which doesn't need updating
        // (as it's pre-generated). We stop recursion.
        if !found_in_levels {
            return Ok(());
        }

        // 2. For each dependency, find its vector index to calculate the expected reward index
        for dep_job_id in deps {
            let mut dep_vector_index: Option<usize> = None;

            // Search in generated job levels
            for level_vec in self.job_levels.iter() {
                if let Some(pos) = level_vec.iter().position(|j| &j.job_id == &dep_job_id) {
                    dep_vector_index = Some(pos);
                    break;
                }
            }

            // If not in job levels, search in input buffer (Level 0 effectively)
            if dep_vector_index.is_none() {
                if let Some(pos) = self.input_buffer.iter().position(|j| &j.job_id == &dep_job_id) {
                    dep_vector_index = Some(pos);
                }
            }

            if let Some(vec_idx) = dep_vector_index {
                // The checker validation logic enforces:
                // expected_index = (parent_index << 1) | vector_index
                let child_reward_index = (index << 1) | (vec_idx as u64);
                self.update_reward_tree_config(&dep_job_id, level + 1, child_reward_index)?;
            } else {
                anyhow::bail!("Dependency job {:?} not found in planner state", dep_job_id);
            }
        }

        Ok(())
    }

    pub async fn finalize_with_reward_ids<Hasher: FieldQHasher<F, Hash>, TempStore: StandardProcessorTempDBStoreBase<QProvingJobDataID, Hash>>(
        mut self,
        realm_identifier: &QRealmIdentifier,
        unique_pending_id: u64,
        current_checkpoint_root: &Hash,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        temp_store: Arc<TempStore>,
        reward_tree_root_level: u8,
        reward_tree_root_index: u64,
        most_recent_checkpoint_global_state_roots: PQEDCheckpointGlobalStateRoots<Hash>,
        most_recent_checkpoint_stats_hash: Hash,
        guta_circuit_whitelist: Hash,
    ) -> anyhow::Result<Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>>>> {
        
        // Handle Empty Case
        if self.input_buffer.is_empty() {
            let checkpoint_state_roots_hash = most_recent_checkpoint_global_state_roots.qfhash::<Hasher>();
            let no_change_input = GUTANoChangeFullInput {
                checkpoint_tree_proof: checkpoint_tree.get_historical_append_only_merkle_proof_for_root(*current_checkpoint_root)?,
                checkpoint_leaf: PQEDCheckpointLeafCompactWithStateRoots {
                    checkpoint_leaf: PQEDCheckpointLeafCompact {
                        global_chain_root: checkpoint_state_roots_hash,
                        stats_hash: most_recent_checkpoint_stats_hash
                    },
                    global_state_roots: most_recent_checkpoint_global_state_roots,
                },
            };
            let expected_public_inputs_hash = no_change_input.get_public_inputs_hash_no_rewards_tag::<F, Hasher>(guta_circuit_whitelist);
            let witness_bytes = no_change_input.psy_ser_to_bytes_vec()?;
            let new_job_id = QProvingJobDataID::new_proof_job_id(
                unique_pending_id,
                0,
                ProvingJobCircuitType::GUTANoChange,
                0,
                0,
            );
            
            temp_store
                .set_tdb_proof_witnesses_tuple_owned_raw(realm_identifier, unique_pending_id, vec![(new_job_id, witness_bytes)])
                .await?;

            let metadata = PsyProvingJobMetadataWithJobId {
                job_id: new_job_id,
                metadata: PsyProvingJobMetadata {
                    expected_public_inputs_hash,
                    reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
                    reward_tree_node_index: reward_tree_root_index,
                    reward_tree_node_level: reward_tree_root_level,
                    reward_tree_node_children: 0,
                    dependencies: vec![],
                },
            };
            return Ok(vec![vec![metadata]]);
        }

        // Convert Inputs to PlannerNodes
        let mut current_nodes: Vec<PlannerNode<F, Hash>> = self.input_buffer.iter().map(|job| {
            PlannerNode {
                job_id: job.job_id,
                header: job.header.header.clone(),
                node_type: PlannerNodeType::InputLeaf,
            }
        }).collect();

        let mut current_processing_level = 0;

        // Special Case: Single Input
        if current_nodes.len() == 1 {
            self.create_singlet_root_promotion_job::<Hasher>(
                current_nodes[0].clone(),
                unique_pending_id,
                checkpoint_tree,
                global_user_tree
            )?;
        } else {
            // Build Tree Bottom-Up
            while current_nodes.len() > 1 {
                let mut next_level_nodes = Vec::new();
                let mut node_iter = current_nodes.into_iter();
                
                while let Some(left) = node_iter.next() {
                    if let Some(right) = node_iter.next() {
                        // Pair found: Aggregate
                        let new_node = self.create_aggregate_job::<Hasher>(
                            left, 
                            right, 
                            unique_pending_id, 
                            current_checkpoint_root, 
                            checkpoint_tree, 
                            global_user_tree, 
                            current_processing_level, 
                            next_level_nodes.len()
                        )?;
                        next_level_nodes.push(new_node);
                    } else {
                        // Odd node out: pass through to next level directly.
                        // It will retain its position in the previous level's vector index logic
                        // but will participate in the next level's pairing.
                        next_level_nodes.push(left);
                    }
                }

                current_nodes = next_level_nodes;
                current_processing_level += 1;
            }
        }

        // Tree is built. The last job added in the last level is the Root.
        let root_job_id = if let Some(last_lvl) = self.job_levels.last() {
            if let Some(root_job) = last_lvl.last() {
                root_job.job_id
            } else {
                anyhow::bail!("Job planner created empty levels");
            }
        } else {
            anyhow::bail!("Job planner failed to create any jobs");
        };

        self.update_reward_tree_config(&root_job_id, reward_tree_root_level, reward_tree_root_index)?;

        // Save witnesses
        temp_store
            .set_tdb_proof_witnesses_tuple_owned_raw(realm_identifier, unique_pending_id, self.job_witnesses)
            .await?;

        Ok(self.job_levels)
    }
}