use std::{collections::HashMap, sync::Arc};
use parth_common::memory_stores::{
    dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore,
    mem_tree_recorder::SimpleMemoryMerkleRecorderStore,
};
use parth_core::{
    crypto::hash::{
        merkle_proof::DeltaMerkleProofCore,
        traits::{FieldQHasher, QFieldHashable},
    },
    data::hash::merkle_node_key::SimpleMerkleNodeKey,
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
        VerifyGUTAToCapCircuitInputSimple,
        GUTAVerifyTwoGUTACircuitInputV2,
        GUTAVerifyTwoGUTALinearCircuitInput,
        GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2,
        VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple,
    },
    v1::qdata::checkpoint::{
        PQEDCheckpointGlobalStateRoots,
        PQEDCheckpointLeafCompact,
        PQEDCheckpointLeafCompactWithStateRoots,
    },
    worker::{
        metadata::{
            PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
            PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD,
            PsyProvingJobMetadata,
        },
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    },
};
use psy_node_core::psy_temp_db::StandardProcessorTempDBStoreBase;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

/// Represents a node in the aggregation tree being built.
#[derive(Clone)]
struct PlannerNode<F, Hash> {
    pub job_id: QProvingJobDataID,
    pub header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub node_type: PlannerNodeType,
    /// The logical height of this node in the aggregation tree.
    /// Input Leaves = 0.
    /// First Level Aggregation = 1.
    pub logical_level: usize,
}

#[derive(Clone, PartialEq, Debug)]
enum PlannerNodeType {
    /// A raw input proof from a realm (Level R)
    InputLeaf,
    /// A proof that has been promoted to a Root transition (Level 0)
    LinearAggregated,
}

pub struct CoordinatorGUTAPlanner<F, Hash> {
    /// Stores witnesses generated during streaming and finalization.
    pub job_witnesses: Vec<(QProvingJobDataID, Vec<u8>)>,
    /// The finalized schedule of jobs. `job_levels[i]` contains jobs at logical height `i+1`.
    pub job_levels: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>>>,
    /// MMR-style waiting buffer. `waiting_nodes[i]` stores a pending tree of logical height `i`.
    waiting_nodes: Vec<Option<PlannerNode<F, Hash>>>,
    queued_updates: Vec<PlannerNode<F, Hash>>,
    has_committed_updates: bool,
    current_synced_checkpoint_root: Hash,
    /// Maps input leaf job_id to realm_id (from header.state_transition.node_index)
    input_job_to_realm: HashMap<QProvingJobDataID, u64>,
    /// Collected realm reward keys after finalize (realm_id -> reward tree position)
    input_realm_reward_keys: HashMap<u64, SimpleMerkleNodeKey>,
}

impl<F, Hash> CoordinatorGUTAPlanner<F, Hash> {
    pub fn new(current_synced_checkpoint_root: Hash) -> Self {
        Self {
            job_witnesses: Vec::new(),
            job_levels: Vec::new(),
            waiting_nodes: Vec::new(),
            queued_updates: Vec::new(),
            has_committed_updates: false,
            current_synced_checkpoint_root,
            input_job_to_realm: HashMap::new(),
            input_realm_reward_keys: HashMap::new(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash + QFHashBase<F>> CoordinatorGUTAPlanner<F, Hash> {
    fn get_leaf_value_after_pending_updates<Hasher: FieldQHasher<F, Hash>>(
        global_user_tree: &SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        pending_updates: &[(u64, Hash)],
        index: u64,
    ) -> Hash {
        pending_updates
            .iter()
            .rev()
            .find_map(|(updated_index, updated_value)| {
                if *updated_index == index {
                    Some(*updated_value)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| global_user_tree.get_e_leaf_value(index))
    }

    fn ensure_input_leaf_matches_global_tree<Hasher: FieldQHasher<F, Hash>>(
        global_user_tree: &SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        header: &GlobalUserTreeAggregatorHeader<F, Hash>,
        pending_updates: &[(u64, Hash)],
    ) -> anyhow::Result<()> {
        let node_index = header.state_transition.node_index.to_u64_value();
        let expected_old_value = header.state_transition.old_node_value;
        let actual_old_value =
            Self::get_leaf_value_after_pending_updates(global_user_tree, pending_updates, node_index);

        if actual_old_value != expected_old_value {
            anyhow::bail!(
                "stale GUTA update: global user tree leaf mismatch at realm index {}: header old leaf {:?}, actual current leaf {:?}, header new leaf {:?}, header checkpoint root {:?}",
                node_index,
                expected_old_value,
                actual_old_value,
                header.state_transition.new_node_value,
                header.checkpoint_tree_root,
            );
        }

        Ok(())
    }

    fn apply_input_leaf_update_to_global_tree<Hasher: FieldQHasher<F, Hash>>(
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        header: &GlobalUserTreeAggregatorHeader<F, Hash>,
    ) -> DeltaMerkleProofCore<Hash> {
        let node_index = header.state_transition.node_index.to_u64_value();
        let dmp = global_user_tree.set_e_leaf(node_index, header.state_transition.new_node_value);
        debug_assert_eq!(dmp.old_value, header.state_transition.old_node_value);
        dmp
    }
    
    /// Adds a realm job and immediately performs any possible aggregations.
    /// This builds perfect binary subtrees on the fly, minimizing work for finalize.
    async fn add_realm_job_internal<Hasher: FieldQHasher<F, Hash>>(
        &mut self,
        unique_pending_id: u64,
        current_checkpoint_root: &Hash,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        mut current_node: PlannerNode<F, Hash>,
    ) -> anyhow::Result<()> {
        

        let mut level_idx = 0;

        // Binary Addition / Folding logic.
        // If we have a waiting node at the current level, it means we have a "Left" sibling.
        // We merge them to create a parent, which then carries over to the next level.
        loop {
            if level_idx >= self.waiting_nodes.len() {
                self.waiting_nodes.push(None);
            }

            if let Some(left_node) = self.waiting_nodes[level_idx].take() {
                // We found a partner. The waiting node is Left (older), current is Right (newer).
                current_node = self.create_aggregate_job::<Hasher>(
                    left_node,
                    current_node,
                    unique_pending_id,
                    current_checkpoint_root,
                    checkpoint_tree,
                    global_user_tree,
                )?;
                
                // Continue up to merge with higher levels if possible
                level_idx += 1;
            } else {
                // Spot is empty, park our current subtree here.
                self.waiting_nodes[level_idx] = Some(current_node);
                break;
            }
        }

        Ok(())
    }

    pub async fn add_realm_job<Hasher: FieldQHasher<F, Hash>, TempStore: StandardProcessorTempDBStoreBase<QProvingJobDataID, Hash>>(
        &mut self,
        unique_pending_id: u64,
        current_checkpoint_root: &Hash,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        _temp_store: Arc<TempStore>,
        job: GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash>,
    ) -> anyhow::Result<()> {
        tracing::info!("adding realm job: {:?}", job.job_id);
        // Record job_id -> realm_id mapping for later use in update_reward_tree_config
        let realm_id = job.header.header.state_transition.node_index.to_u64_value();
        self.input_job_to_realm.insert(job.job_id, realm_id);

        let current_node = PlannerNode {
            job_id: job.job_id,
            header: job.header.header,
            node_type: PlannerNodeType::InputLeaf,
            logical_level: 0,
        };
        if self.has_committed_updates {
            tracing::info!("adding update directly, already committed updates");
            self.add_realm_job_internal::<Hasher>(unique_pending_id, current_checkpoint_root, checkpoint_tree, global_user_tree, current_node).await?;
        }else{
            if current_checkpoint_root != &self.current_synced_checkpoint_root {
                tracing::info!("committing queued updates, checkpoint root changed from {:?} to {:?}", self.current_synced_checkpoint_root, current_checkpoint_root);
                // we are ready for committing updates
                self.has_committed_updates = true;
                let queued_updates = {
                    std::mem::take(&mut self.queued_updates)
                };  
                for queued_update in queued_updates {
                    self.add_realm_job_internal::<Hasher>(unique_pending_id, current_checkpoint_root, checkpoint_tree, global_user_tree, queued_update).await?;
                }
                self.add_realm_job_internal::<Hasher>(unique_pending_id, current_checkpoint_root, checkpoint_tree, global_user_tree, current_node).await?;
            }else{
                tracing::info!("queuing update, checkpoint root unchanged {:?}", current_checkpoint_root);
                // queue the update
                self.queued_updates.push(current_node);
            }
        }

        

        Ok(())
    }

    /// Core aggregation logic. Selects the correct circuit based on input types.
    fn create_aggregate_job<Hasher: FieldQHasher<F, Hash>>(
        &mut self,
        left: PlannerNode<F, Hash>,
        right: PlannerNode<F, Hash>,
        unique_pending_id: u64,
        current_checkpoint_root: &Hash,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    ) -> anyhow::Result<PlannerNode<F, Hash>> {
        let left_is_leaf = left.node_type == PlannerNodeType::InputLeaf;
        let right_is_leaf = right.node_type == PlannerNodeType::InputLeaf;

        let left_cp = left.header.checkpoint_tree_root;
        let right_cp = right.header.checkpoint_tree_root;
        
        let left_needs_cp_upgrade = left_is_leaf && (&left_cp != current_checkpoint_root);
        let right_needs_cp_upgrade = right_is_leaf && (&right_cp != current_checkpoint_root);

        // Calculate the logical level of the new node.
        // It sits one step above the highest parent.
        let new_logical_level = std::cmp::max(left.logical_level, right.logical_level) + 1;
        
        // Ensure job_levels has space. 
        // logical_level 1 (first aggregations) goes to index 0.
        if self.job_levels.len() < new_logical_level {
            self.job_levels.resize(new_logical_level, Vec::new());
        }
        let level_vec_idx = new_logical_level - 1;
        let item_idx = self.job_levels[level_vec_idx].len();

        let (witness_bytes, new_header, circuit_type) = if left_is_leaf && right_is_leaf {
            // Level R -> Level 0 Promotion
            Self::ensure_input_leaf_matches_global_tree::<Hasher>(
                global_user_tree,
                &left.header,
                &[],
            )?;

            let left_pending_update = [(
                left.header.state_transition.node_index.to_u64_value(),
                left.header.state_transition.new_node_value,
            )];
            Self::ensure_input_leaf_matches_global_tree::<Hasher>(
                global_user_tree,
                &right.header,
                &left_pending_update,
            )?;

            let left_dmp =
                Self::apply_input_leaf_update_to_global_tree::<Hasher>(global_user_tree, &left.header);
            let right_dmp =
                Self::apply_input_leaf_update_to_global_tree::<Hasher>(global_user_tree, &right.header);

            if left_needs_cp_upgrade || right_needs_cp_upgrade {
                // Get the current checkpoint index to build upgrade proofs with the CURRENT root
                let current_checkpoint_index = checkpoint_tree
                    .get_leaf_index_for_root(*current_checkpoint_root)
                    .ok_or_else(|| anyhow::anyhow!(
                        "Current checkpoint root {:?} not found in checkpoint tree",
                        current_checkpoint_root
                    ))?;

                let input = GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2 {
                    left_header: left.header,
                    left_global_user_tree_delta_merkle_proof: left_dmp,
                    left_historical_checkpoint_merkle_proof: checkpoint_tree.get_historical_index_append_only_merkle_proof_for_root(left_cp, current_checkpoint_index)?,
                    right_header: right.header,
                    right_global_user_tree_delta_merkle_proof: right_dmp,
                    right_historical_checkpoint_merkle_proof: checkpoint_tree.get_historical_index_append_only_merkle_proof_for_root(right_cp, current_checkpoint_index)?,
                };
                (
                    input.psy_ser_to_bytes_vec()?,
                    input.get_new_guta_header(),
                    ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade,
                )
            } else {
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
            // Level 0 -> Level 0 Aggregation
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
            // Mixed: Aggregated (Left) + Leaf (Right)
            Self::ensure_input_leaf_matches_global_tree::<Hasher>(
                global_user_tree,
                &right.header,
                &[],
            )?;
            let right_dmp =
                Self::apply_input_leaf_update_to_global_tree::<Hasher>(global_user_tree, &right.header);

            // Get the current checkpoint index to build upgrade proof with the CURRENT root
            // Note: left is already at current checkpoint (validated above), so we use left_cp's index
            let current_checkpoint_index = checkpoint_tree
                .get_leaf_index_for_root(*current_checkpoint_root)
                .ok_or_else(|| anyhow::anyhow!(
                    "Current checkpoint root {:?} not found in checkpoint tree",
                    current_checkpoint_root
                ))?;

            let input = GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput {
                left_header: left.header,
                right_header: right.header,
                right_global_user_tree_delta_merkle_proof: right_dmp,
                right_historical_checkpoint_proof: checkpoint_tree.get_historical_index_append_only_merkle_proof_for_root(right_cp, current_checkpoint_index)?,
            };
            
            (
                input.psy_ser_to_bytes_vec()?,
                input.get_new_guta_header(),
                ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint,
            )
        } else {
            // Left=Leaf, Right=Linear.
            // This case should not occur with strict Left-to-Right stream processing 
            // unless we fold out of order.
            anyhow::bail!("Invalid aggregation pair: Left=Leaf, Right=Linear.");
        };

        let new_job_id = QProvingJobDataID::new_proof_job_id(
            unique_pending_id,
            level_vec_idx as u32,
            circuit_type,
            0,
            item_idx as u32,
        );

        self.job_witnesses.push((new_job_id, witness_bytes));

        let mut metadata = GlobalUserTreeAggregatorHeaderWithJobId{
            header: new_header.clone(),
            job_id: new_job_id,
        }.to_metadata_with_job_standard_children::<Hasher>(vec![left.job_id, right.job_id]);
        
        metadata.job_id = new_job_id;
        
        self.job_levels[level_vec_idx].push(metadata);

        Ok(PlannerNode {
            job_id: new_job_id,
            header: new_header,
            node_type: PlannerNodeType::LinearAggregated,
            logical_level: new_logical_level,
        })
    }

    /// Handles single-input case where we just promote one leaf to root.
    fn create_singlet_root_promotion_job<Hasher: FieldQHasher<F, Hash>>(
        &mut self,
        node: PlannerNode<F, Hash>,
        unique_pending_id: u64,
        current_checkpoint_root: &Hash,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    ) -> anyhow::Result<GlobalUserTreeAggregatorHeader<F, Hash>> {
        if node.node_type != PlannerNodeType::InputLeaf {
             // If it's already linear, it's already a root proof. No action needed.
             return Ok(node.header);
        }

        Self::ensure_input_leaf_matches_global_tree::<Hasher>(
            global_user_tree,
            &node.header,
            &[],
        )?;
        let dmp =
            Self::apply_input_leaf_update_to_global_tree::<Hasher>(global_user_tree, &node.header);

        let (witness_bytes, new_header, circuit_type) =
            if node.header.checkpoint_tree_root == *current_checkpoint_root {
                let input = VerifyGUTAToCapCircuitInputSimple {
                    guta_proof_header: node.header,
                    top_line_siblings: dmp.siblings,
                };
                (
                    input.psy_ser_to_bytes_vec()?,
                    input.get_new_guta_header::<Hasher>(),
                    ProvingJobCircuitType::GUTAVerifyToCap,
                )
            } else {
                let current_checkpoint_index = checkpoint_tree
                    .get_leaf_index_for_root(*current_checkpoint_root)
                    .ok_or_else(|| anyhow::anyhow!(
                        "Current checkpoint root {:?} not found in checkpoint tree",
                        current_checkpoint_root
                    ))?;

                let input = VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple {
                    guta_proof_header: node.header,
                    top_line_siblings: dmp.siblings,
                    historical_checkpoint_proof: checkpoint_tree.get_historical_index_append_only_merkle_proof_for_root(node.header.checkpoint_tree_root, current_checkpoint_index)?,
                    total_aggregation_proofs_generated: node.header.total_aggregation_proofs_generated,
                };

                (
                    input.psy_ser_to_bytes_vec()?,
                    input.get_new_guta_header::<Hasher>(),
                    ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade,
                )
            };
        let expected_hash = new_header.qfhash::<Hasher>();

        let new_job_id = QProvingJobDataID::new_proof_job_id(
            unique_pending_id,
            0,
            circuit_type,
            0,
            0,
        );

        self.job_witnesses.push((new_job_id, witness_bytes));
        
        let metadata = PsyProvingJobMetadataWithJobId {
            job_id: new_job_id,
            metadata: PsyProvingJobMetadata {
                expected_public_inputs_hash: expected_hash,
                reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD,
                reward_tree_node_index: 0,
                reward_tree_node_level: 0,
                reward_tree_node_children: 1,
                dependencies: vec![node.job_id],
            },
        };

        if self.job_levels.is_empty() {
            self.job_levels.push(Vec::new());
        }
        self.job_levels[0].push(metadata);

        Ok(new_header)
    }

    fn update_reward_tree_config(
        &mut self,
        job_id: &QProvingJobDataID,
        level: u8,
        index: u64,
    ) -> anyhow::Result<()> {
        let mut deps = Vec::new();
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

        if !found_in_levels {
            if let Some(realm_id) = self.input_job_to_realm.get(job_id) {
                self.input_realm_reward_keys.insert(*realm_id, SimpleMerkleNodeKey { level, index });
            }
            return Ok(());
        }

        for (child_pos, dep_job_id) in deps.into_iter().enumerate() {
            let child_reward_index = (index << 1) + (child_pos as u64);
            self.update_reward_tree_config(&dep_job_id, level + 1, child_reward_index)?;
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
    ) -> anyhow::Result<(
        Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>>>,
        HashMap<u64, SimpleMerkleNodeKey>,
        GlobalUserTreeAggregatorHeader<F, Hash>,
    )> {
        if !self.has_committed_updates {
            // No updates were committed yet, so we need to process queued updates now.
            let queued_updates = {
                std::mem::take(&mut self.queued_updates)
            };
            for queued_update in queued_updates {
                self.add_realm_job_internal::<Hasher>(unique_pending_id, current_checkpoint_root, checkpoint_tree, global_user_tree, queued_update).await?;
            }
        }
        tracing::info!("Finalizing GUTA Planner with {} waiting nodes.", self.waiting_nodes.len());
        // 1. Gather all pending subtrees.
        // We use std::mem::take to satisfy borrow checker rules, allowing us to mutate self later.
        // The waiting_nodes are ordered by power-of-2 size (index 0 = height 0, index 1 = height 1).
        // High indices are naturally to the LEFT of Low indices in the stream.
        // Reversing the iterator gives us High-to-Low index, which corresponds to Left-to-Right stream order.
        let mut active_nodes: Vec<PlannerNode<F, Hash>> = std::mem::take(&mut self.waiting_nodes)
            .into_iter()
            .rev()
            .filter_map(|n| n)
            .collect();

        // 2. Reduce using Right-to-Left folding.
        // We merge the right-most (smallest/latest) trees first.
        // This allows smaller trees to "grow" in height before merging with larger trees to the left,
        // resulting in a tree with minimal height (log2_ceil(N)).
        while active_nodes.len() > 1 {
            // Pop the last two (Right-most)
            let right = active_nodes.pop().unwrap();
            let left = active_nodes.pop().unwrap();
            
            // Merge them
            let parent = self.create_aggregate_job::<Hasher>(
                left, 
                right, 
                unique_pending_id, 
                current_checkpoint_root, 
                checkpoint_tree, 
                global_user_tree
            )?;

            // Push the result back as the new Right-most node
            active_nodes.push(parent);
        }

        // 3. Handle Result
        let root_guta_header = if let Some(root_node) = active_nodes.pop() {
            // If single node remains, promote if it's a leaf.
            let root_guta_header = if root_node.node_type == PlannerNodeType::InputLeaf {
                tracing::info!("Promoting single GUTA update to cap/root proof.");
                self.create_singlet_root_promotion_job::<Hasher>(
                    root_node, 
                    unique_pending_id, 
                    current_checkpoint_root,
                    checkpoint_tree, 
                    global_user_tree
                )?
            }else{
                tracing::info!("GUTA updates processed, root proof is already linear.");
                root_node.header
            };
            
            // Note: If root_node was already Linear, it is the root proof.
            // We need to find its ID in job_levels to configure rewards.
            let root_job_id = self.job_levels.iter().flatten().last()
                .map(|j| j.job_id)
                .ok_or_else(|| anyhow::anyhow!("Planner state error: Active node exists but job list empty"))?;

            self.update_reward_tree_config(&root_job_id, reward_tree_root_level, reward_tree_root_index)?;
            root_guta_header

        } else {
            // No inputs -> No Change Proof
            tracing::info!("No GUTA updates to process, generating No-Change proof.");
            let checkpoint_state_roots_hash = most_recent_checkpoint_global_state_roots.qfhash::<Hasher>();
            let current_checkpoint_index = checkpoint_tree
                .get_leaf_index_for_root(*current_checkpoint_root)
                .ok_or_else(|| anyhow::anyhow!(
                    "Current checkpoint root {:?} not found in checkpoint tree",
                    current_checkpoint_root
                ))?;
            let no_change_input = GUTANoChangeFullInput {
                checkpoint_tree_proof: checkpoint_tree.get_historical_index_append_only_merkle_proof_for_root(*current_checkpoint_root, current_checkpoint_index)?,
                checkpoint_leaf: PQEDCheckpointLeafCompactWithStateRoots {
                    checkpoint_leaf: PQEDCheckpointLeafCompact {
                        global_chain_root: checkpoint_state_roots_hash,
                        stats_hash: most_recent_checkpoint_stats_hash
                    },
                    global_state_roots: most_recent_checkpoint_global_state_roots,
                },
            };
            let root_guta_header = GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist,
                checkpoint_tree_root: no_change_input.checkpoint_tree_proof.root,
                state_transition: psy_data::guta::sub_tree_transition::SubTreeNodeStateTransition {
                    old_node_value: no_change_input.checkpoint_leaf.global_state_roots.user_tree_root,
                    new_node_value: no_change_input.checkpoint_leaf.global_state_roots.user_tree_root,
                    node_index: F::ZERO_VALUE,
                    node_level: F::ZERO_VALUE,
                },
                stats: psy_data::guta::stats::GUTAStats::<F>::get_zero_value(),
                total_aggregation_proofs_generated: F::from_u8_value(1),
            };
            let expected_public_inputs_hash = no_change_input.get_public_inputs_hash_no_rewards_tag::<F, Hasher>(guta_circuit_whitelist);
            println!(
                "Coordinator no-change metadata root={:?} expected_public_inputs_hash={:?}",
                guta_circuit_whitelist,
                expected_public_inputs_hash
            );
            let witness_bytes = no_change_input.psy_ser_to_bytes_vec()?;
            let new_job_id = QProvingJobDataID::new_proof_job_id(
                unique_pending_id,
                0,
                ProvingJobCircuitType::GUTANoChange,
                0,
                0,
            );
            
            self.job_witnesses.push((new_job_id.get_input_witness_id(), witness_bytes));

            let metadata = PsyProvingJobMetadataWithJobId {
                job_id: new_job_id.get_output_id(),
                metadata: PsyProvingJobMetadata {
                    expected_public_inputs_hash,
                    reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
                    reward_tree_node_index: reward_tree_root_index,
                    reward_tree_node_level: reward_tree_root_level,
                    reward_tree_node_children: 0,
                    dependencies: vec![],
                },
            };
            self.job_levels.push(vec![metadata]);
            root_guta_header
        };

        // 4. Save witnesses
        if !self.job_witnesses.is_empty() {
             temp_store
            .set_tdb_proof_witnesses_tuple_owned_raw(realm_identifier, unique_pending_id, self.job_witnesses)
            .await?;
        }

        Ok((self.job_levels, self.input_realm_reward_keys, root_guta_header))
    }
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use cf_utils::timer::DebugTimer;

    use parth_common::memory_stores::{
        dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, mem_tree_recorder::SimpleMemoryMerkleRecorderStore,
        traits::PsyMemoryMerkleStoreImm,
    };
    use parth_core::{
        crypto::hash::traits::{FieldQHasher, MerkleZeroHasher, QFieldHashable},
        felt::{FromPrimitiveValuesFelt, ZeroableFelt},
        node::realm_identifier::QRealmIdentifier,
        pgoldilocks::PoseidonHasher,
        utils::{QPGenRandom, math::log2_ceil},
    };
    use psy_core::job::
        job_id::{ProvingJobCircuitType, ProvingJobDataType, QJobTopic, QProvingJobDataID}
    ;
    use psy_data::{
        guta::{
            header::GlobalUserTreeAggregatorHeader,
            header_extended::{GlobalUserTreeAggregatorHeaderWithJobId, GlobalUserTreeAggregatorHeaderWithTagValue, GlobalUserTreeAggregatorHeaderWithTagValueAndJobID},
            stats::GUTAStats,
            sub_tree_transition::SubTreeNodeStateTransition,
        }, proof_input::guta::{GUTANoChangeFullInput, GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput, GUTAVerifyTwoGUTACircuitInputV2, GUTAVerifyTwoGUTALinearCircuitInput, GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2, VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple}, v1::qdata::{
            checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafCompact, PQEDCheckpointLeafStats},
            pm_jobs_completed_stats::PPMJobsCompletedStats,
            pm_rewards_commitment::PPMRewardCommitment,
        }, worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId
    };
    use psy_node_core::psy_temp_db::StandardProcessorTempDBStoreBase;
    use psy_node_store_memory::temp_store::InMemoryTempStore;
    use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
    use rand::Rng;

    use super::CoordinatorGUTAPlanner;

    type F = parth_core::PF;
    type Hash = parth_core::PHash;
    type Hasher = PoseidonHasher;
    const REALM_LEVEL: usize = 12;
    const REALM_LEVEL_U8: u8 = REALM_LEVEL as u8;
    struct JobCorrectnessChecker {
        pub jobs: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>>>,
    }
    impl JobCorrectnessChecker {
        pub fn new(input_jobs: Vec<PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>>, result_jobs: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>>>) -> Self {
            Self { jobs: [vec![input_jobs], result_jobs].concat() }
        }
        pub fn get_job_level_index_by_id(
            &self,
            job_id: &QProvingJobDataID,
        ) -> anyhow::Result<(usize, usize, &PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>)> {
            for (level_index, level_jobs) in self.jobs.iter().enumerate() {
                for (job_index, job_metadata) in level_jobs.iter().enumerate() {
                    if &job_metadata.job_id == job_id {
                        return Ok((level_index, job_index, job_metadata));
                    }
                }
            }
            Err(anyhow::anyhow!("Job id {:?} not found in planner", job_id))
        }
        pub fn is_job_input_proof(&self, job_id: &QProvingJobDataID) -> anyhow::Result<bool> {
            if job_id.circuit_type == ProvingJobCircuitType::GUTATwoEndCap {
                return Ok(true);
            }else{
                return Ok(false);
            }
        }
        pub fn process_job_witness<'a, TempStore>(
            &'a self,
            realm_identifier: &'a QRealmIdentifier,
            unique_pending_id: u64,
            temp_store: Arc<TempStore>,
            job_id: QProvingJobDataID,
            guta_circuit_whitelist: Hash,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<SubTreeNodeStateTransition<F, Hash>>> + Send + 'a>>
        where
            TempStore: StandardProcessorTempDBStoreBase<QProvingJobDataID, Hash> + Send + Sync + 'a,
        {
            Box::pin(async move {
                let data: Vec<u8> = temp_store.get_tdb_proof_witness_bytes(realm_identifier, unique_pending_id, job_id).await?;
                let (state_transition, computed_public_inputs_hash) = match job_id.circuit_type {
                    ProvingJobCircuitType::GUTATwoGUTA => {
                        let witness = GUTAVerifyTwoGUTACircuitInputV2::<F, Hash>::psy_ser_from_slice(&data)?;
                        (witness.get_new_guta_header().state_transition, witness.get_public_inputs_hash_no_rewards_tag::<Hasher>())
                    },
                    ProvingJobCircuitType::GUTANoChange => {
                        let witness: GUTANoChangeFullInput<Hash> = GUTANoChangeFullInput::<Hash>::psy_ser_from_slice(&data)?;
                        (
                            SubTreeNodeStateTransition {
                                old_node_value: witness.checkpoint_leaf.global_state_roots.user_tree_root,
                                new_node_value: witness.checkpoint_leaf.global_state_roots.user_tree_root,
                                node_index: F::ZERO_VALUE,
                                node_level: F::ZERO_VALUE,
                            },
                            witness.get_public_inputs_hash_no_rewards_tag::<F, Hasher>(guta_circuit_whitelist)
                        )
                    },
                    ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade => {
                        let witness = GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2::<F, Hash>::psy_ser_from_slice(&data)?;
                        (witness.get_new_guta_header().state_transition, witness.get_public_inputs_hash_no_rewards_tag::<Hasher>())
                    },
                    ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade => {
                        let witness = VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple::<F, Hash>::psy_ser_from_slice(&data)?;
                        (witness.get_new_guta_header::<Hasher>().state_transition, witness.get_public_inputs_hash_no_rewards_tag::<Hasher>())
                    },
                    ProvingJobCircuitType::GUTATwoGUTALinear => {
                        let witness = GUTAVerifyTwoGUTALinearCircuitInput::<F, Hash>::psy_ser_from_slice(&data)?;
                        (witness.get_new_guta_header().state_transition, witness.get_public_inputs_hash_no_rewards_tag::<Hasher>())
                    },
                    ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint => {
                        let witness = GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput::<F, Hash>::psy_ser_from_slice(&data)?;
                        (witness.get_new_guta_header().state_transition, witness.get_public_inputs_hash_no_rewards_tag::<Hasher>())
                    },
                    _ => {
                        return Err(anyhow::anyhow!("Unsupported job circuit type {:?}", job_id.circuit_type));
                    }
                };
                let job = self.get_job_level_index_by_id(&job_id)?.2;
                let expected_public_inputs_hash = job.metadata.expected_public_inputs_hash;
                if computed_public_inputs_hash != expected_public_inputs_hash {
                    return Err(anyhow::anyhow!(
                        "Job {:?} public inputs hash mismatch: computed {:?}, expected {:?}",
                        job_id,
                        computed_public_inputs_hash,
                        expected_public_inputs_hash
                    ));
                }

                if job.metadata.dependencies.len() == 2 {
                    let is_left_input_child_proof = self.is_job_input_proof(&job.metadata.dependencies[0])?;
                    let is_right_input_child_proof = self.is_job_input_proof(&job.metadata.dependencies[1])?;
                    if !is_left_input_child_proof {
                        let left_child_state_transition = self.process_job_witness(
                            realm_identifier,
                            unique_pending_id,
                            temp_store.clone(),
                            job.metadata.dependencies[0].clone(),
                            guta_circuit_whitelist.clone(),
                        ).await?;
                        if left_child_state_transition.node_index != state_transition.node_index {
                            return Err(anyhow::anyhow!(
                                "Linear Job {:?} left child node index mismatch: child {:?}, parent {:?}",
                                job_id,
                                left_child_state_transition.node_index,
                                state_transition.node_index
                            ));
                        } else if left_child_state_transition.node_level != state_transition.node_level {
                            return Err(anyhow::anyhow!(
                                "Linear Job {:?} left child node level mismatch: child {:?}, parent {:?}",
                                job_id,
                                left_child_state_transition.node_level,
                                state_transition.node_level
                            ));
                        } else if left_child_state_transition.old_node_value != state_transition.old_node_value {
                            return Err(anyhow::anyhow!(
                                "Linear Job {:?} left child old node value mismatch: child {:?}, parent {:?}",
                                job_id,
                                left_child_state_transition.old_node_value,
                                state_transition.old_node_value
                            ));
                        }
                        if !is_right_input_child_proof {
                            let right_child_state_transition = self.process_job_witness(
                                realm_identifier,
                                unique_pending_id,
                                    temp_store.clone(),
                                job.metadata.dependencies[1].clone(),
                                guta_circuit_whitelist.clone(),
                            ).await?;
                            if right_child_state_transition.node_index != state_transition.node_index {
                                return Err(anyhow::anyhow!(
                                    "Linear Job {:?} right child node index mismatch: child {:?}, parent {:?}",
                                    job_id,
                                    right_child_state_transition.node_index,
                                    state_transition.node_index
                                ));
                            } else if right_child_state_transition.node_level != state_transition.node_level {
                                return Err(anyhow::anyhow!(
                                    "Linear Job {:?} right child node level mismatch: child {:?}, parent {:?}",
                                    job_id,
                                    right_child_state_transition.node_level,
                                    state_transition.node_level
                                ));
                            } else if right_child_state_transition.old_node_value != left_child_state_transition.new_node_value {
                                return Err(anyhow::anyhow!(
                                    "Linear Job {:?} is not back to back, left.new_node_value {:?} != right.old_node_value {:?}",
                                    job_id,
                                    left_child_state_transition.new_node_value,
                                    right_child_state_transition.old_node_value
                                ));
                            } else if right_child_state_transition.new_node_value != state_transition.new_node_value {
                                return Err(anyhow::anyhow!(
                                    "Linear Job {:?} right child new node value mismatch: child {:?}, parent {:?}",
                                    job_id,
                                    right_child_state_transition.new_node_value,
                                    state_transition.new_node_value
                                ));
                            }
                        } else {
                            // No-op for else branch
                        }
                    }
                }
                Ok(state_transition)
            })
        }
        pub fn check_jobs_correctness<Hasher: FieldQHasher<F, Hash>>(&self) -> anyhow::Result<()> {
            for level in 1..self.jobs.len() {
                for job_metadata in &self.jobs[level] {
                    for (dep_index, dep_job_id) in job_metadata.metadata.dependencies.iter().enumerate() {
                        let (dep_level, _, dep_job_metadata) = self.get_job_level_index_by_id(dep_job_id)?;
                        if dep_level >= level {
                            return Err(anyhow::anyhow!(
                                "Job {:?} at level {} depends on job {:?} at level {} which is not lower",
                                job_metadata.job_id,
                                level,
                                dep_job_id,
                                dep_level
                            ));
                        }
                        let is_dep_input_proof = self.is_job_input_proof(dep_job_id)?;
                        let expected_rewards_tree_node_level = job_metadata.metadata.reward_tree_node_level + 1;
                        let expected_rewards_tree_node_index = (job_metadata.metadata.reward_tree_node_index << 1) | (dep_index as u64);
                        if dep_job_metadata.metadata.reward_tree_node_level != expected_rewards_tree_node_level && !is_dep_input_proof{
                            return Err(anyhow::anyhow!(
                                "Job {:?} at level {} depends on job {:?} at level {} which has incorrect reward tree node level {}, expected {}",
                                job_metadata.job_id,
                                level,
                                dep_job_id,
                                dep_level,
                                dep_job_metadata.metadata.reward_tree_node_level,
                                expected_rewards_tree_node_level
                            ));
                        }
                        if dep_job_metadata.metadata.reward_tree_node_index != expected_rewards_tree_node_index && !is_dep_input_proof {
                            return Err(anyhow::anyhow!(
                                "Job {:?} at level {} depends on job {:?} at level {} which has incorrect reward tree node index {}, expected {}",
                                job_metadata.job_id,
                                level,
                                dep_job_id,
                                dep_level,
                                dep_job_metadata.metadata.reward_tree_node_index,
                                expected_rewards_tree_node_index
                            ));
                        }
                    }

                    if job_metadata.metadata.dependencies.len() == 2 {
                        let left_dep = &job_metadata.metadata.dependencies[0];
                        let right_dep = &job_metadata.metadata.dependencies[1];
                        let left_is_input_proof = self.is_job_input_proof(left_dep)?;
                        let right_is_input_proof = self.is_job_input_proof(right_dep)?;
                        let left_needs_checkpoint_upgrade = left_is_input_proof && left_dep.goal_id == 0;
                        let right_needs_checkpoint_upgrade = right_is_input_proof && right_dep.goal_id == 0;
                        let parent_job_circuit_type = job_metadata.job_id.circuit_type;
                        if left_is_input_proof && right_is_input_proof {
                            if parent_job_circuit_type == ProvingJobCircuitType::GUTATwoGUTA {
                                if left_needs_checkpoint_upgrade || right_needs_checkpoint_upgrade {
                                    return Err(anyhow::anyhow!(
                                        "Job {:?} is GUTATwoGUTA but one of its input proofs needs checkpoint upgrade",
                                        job_metadata.job_id
                                    ));
                                }
                            } else if parent_job_circuit_type == ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade {
                                if !left_needs_checkpoint_upgrade && !right_needs_checkpoint_upgrade {
                                    return Err(anyhow::anyhow!(
                                        "Job {:?} is GUTATwoGUTAWithCheckpointUpgrade but none of its input proofs needs checkpoint upgrade",
                                        job_metadata.job_id
                                    ));
                                }
                            } else {
                                return Err(anyhow::anyhow!(
                                    "Job {:?} has unexpected circuit type {:?} for two input proofs",
                                    job_metadata.job_id,
                                    parent_job_circuit_type
                                ));
                            }
                        } else if left_is_input_proof && !right_is_input_proof {
                            anyhow::bail!(
                                "Job {:?} has left input proof as input proof but right is not, which is unexpected",
                                job_metadata.job_id
                            );
                        } else if !left_is_input_proof && right_is_input_proof {
                            if parent_job_circuit_type != ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint {
                                return Err(anyhow::anyhow!(
                                    "Job {:?} has right input proof as input proof but left is not, expected circuit type GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint but got {:?}",
                                    job_metadata.job_id,
                                    parent_job_circuit_type
                                ));
                            }
                        } else {
                            // Both are non-input proofs
                            if parent_job_circuit_type != ProvingJobCircuitType::GUTATwoGUTALinear {
                                return Err(anyhow::anyhow!(
                                    "Job {:?} has two non-input proofs but unexpected circuit type {:?}",
                                    job_metadata.job_id,
                                    parent_job_circuit_type
                                ));
                            }
                        }
                    } else if job_metadata.metadata.dependencies.len() == 1 {
                        let dep = &job_metadata.metadata.dependencies[0];
                        let dep_is_input_proof = self.is_job_input_proof(dep)?;
                        // let dep_needs_checkpoint_upgrade = dep_is_input_proof && dep.goal_id == 0;
                        let parent_job_circuit_type = job_metadata.job_id.circuit_type;
                        if dep_is_input_proof {
                            if parent_job_circuit_type == ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade {
                                if !dep_is_input_proof {
                                    return Err(anyhow::anyhow!(
                                        "Job {:?} is GUTAVerifyToCapWithCheckpointUpgrade but its input proof does not need checkpoint upgrade",
                                        job_metadata.job_id
                                    ));
                                }
                            } else {
                                return Err(anyhow::anyhow!(
                                    "Job {:?} has unexpected circuit type {:?} for single input proof",
                                    job_metadata.job_id,
                                    parent_job_circuit_type
                                ));
                            }
                        } else {
                            return Err(anyhow::anyhow!(
                                "Job {:?} has non-input proof as single dependency, which is unexpected",
                                job_metadata.job_id
                            ));
                        }
                    } else {
                        if job_metadata.job_id.circuit_type != ProvingJobCircuitType::GUTANoChange {
                            return Err(anyhow::anyhow!(
                                "Job {:?} has {} dependencies, expected 1 or 2 or 0 for no change proof",
                                job_metadata.job_id,
                                job_metadata.metadata.dependencies.len()
                            ));
                        } else if job_metadata.metadata.dependencies.len() != 0 {
                            return Err(anyhow::anyhow!(
                                "Job {:?} is GUTANoChange but has {} dependencies, expected 0",
                                job_metadata.job_id,
                                job_metadata.metadata.dependencies.len()
                            ));
                        }
                    }
                }
            }

            Ok(())
        }
        /*
        pub fn generate_graph_viz(&self) -> anyhow::Result<String> {
            use std::fmt::Write;

            let mut dot = String::new();
            writeln!(dot, "digraph G {{")?;

            // 1. Global Graph Attributes
            // BT = Bottom to Top. Since Level 0 are inputs and Level N is root,
            // this puts inputs at the bottom and root at the top.
            writeln!(dot, "  rankdir=BT;")?; 
            writeln!(dot, "  compound=true;")?;
            writeln!(dot, "  splines=ortho;")?; // Circuit-board style lines
            writeln!(dot, "  nodesep=0.4;")?;
            writeln!(dot, "  ranksep=0.6;")?;
            writeln!(dot, "  fontname=\"Courier\";")?; // Monospace for a technical look
            writeln!(dot, "  node [shape=plain, fontname=\"Courier\", fontsize=10];")?;
            writeln!(dot, "  edge [color=\"black\", arrowhead=vee, penwidth=1.0];")?;
            writeln!(dot, "  bgcolor=\"white\";")?;

            // 2. Node Generation grouped by Levels
            for (level_idx, level_jobs) in self.jobs.iter().enumerate() {
                
                // Level Clusters: Dashed grey lines, no fill
                writeln!(dot, "  subgraph cluster_{} {{", level_idx)?;
                writeln!(dot, "    label=\"Level {}\";", level_idx)?;
                writeln!(dot, "    style=\"dashed\";")?;
                writeln!(dot, "    color=\"#555555\";")?;
                writeln!(dot, "    fontcolor=\"#555555\";")?;
                writeln!(dot, "    fontsize=10;")?;
                writeln!(dot, "    labelloc=\"b\";")?; // Label at bottom

                for (job_index, job) in level_jobs.iter().enumerate() {
                    let node_id = format!("job_{}_{}", level_idx, job_index);

                    // Extract Circuit Type for the Header
                    // We format the debug string and split it to get a cleaner display name
                    let circuit_type_debug = format!("{:?}", job.job_id.circuit_type);
                    // Optional: Cleanup "ProvingJobCircuitType::" prefix if present in debug output
                    let display_type = circuit_type_debug.replace("ProvingJobCircuitType::", "");

                    let reward_lvl = job.metadata.reward_tree_node_level;
                    let reward_idx = job.metadata.reward_tree_node_index;
                    
                    // High Contrast Node Design
                    // Header: Black BG, White Text
                    // Body: White BG, Black Text
                    writeln!(dot, "    {} [label=<", node_id)?;
                    writeln!(
                        dot,
                        "      <TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\" CELLPADDING=\"4\" BGCOLOR=\"white\" STYLE=\"ROUNDED\">"
                    )?;

                    // Header Row (Circuit Type)
                    writeln!(
                        dot, 
                        "        <TR><TD COLSPAN=\"2\" BGCOLOR=\"black\"><FONT COLOR=\"white\"><B>{}</B></FONT></TD></TR>", 
                        display_type
                    )?;

                    // Job Details
                    writeln!(dot, "        <TR>")?;
                    writeln!(dot, "          <TD ALIGN=\"LEFT\">Rwd Lvl:</TD>")?;
                    writeln!(dot, "          <TD ALIGN=\"RIGHT\">{}</TD>", reward_lvl)?;
                    writeln!(dot, "        </TR>")?;
                    writeln!(dot, "        <TR>")?;
                    writeln!(dot, "          <TD ALIGN=\"LEFT\">Rwd Idx:</TD>")?;
                    writeln!(dot, "          <TD ALIGN=\"RIGHT\">{}</TD>", reward_idx)?;
                    writeln!(dot, "        </TR>")?;

                    // Conditional: Mark Input Proofs distinctively in the text
                    if self.is_job_input_proof(&job.job_id)? {
                         writeln!(dot, "        <TR><TD COLSPAN=\"2\" ALIGN=\"CENTER\"><I>Input Leaf</I></TD></TR>")?;
                         writeln!(dot, "        <TR><TD COLSPAN=\"2\" ALIGN=\"CENTER\"><I>Checkpoint {}</I></TD></TR>", job.job_id.goal_id)?;
                    }

                    writeln!(dot, "      </TABLE>")?;
                    writeln!(dot, "    >];")?;
                }
                writeln!(dot, "  }}")?; // End subgraph
            }

            // 3. Edge Generation
            for (level_idx, level_jobs) in self.jobs.iter().enumerate() {
                for (job_index, job) in level_jobs.iter().enumerate() {
                    let parent_node_id = format!("job_{}_{}", level_idx, job_index);

                    for dep_job_id in &job.metadata.dependencies {
                        if let Ok((dep_level, dep_index, _)) = self.get_job_level_index_by_id(dep_job_id) {
                            let child_node_id = format!("job_{}_{}", dep_level, dep_index);
                            
                            // Standard edge
                            writeln!(dot, "  {} -> {};", child_node_id, parent_node_id)?;
                        } else {
                            // Error/Missing edge
                            let ghost_id = format!("missing_{:?}", dep_job_id).replace(" ", "_").replace("(", "").replace(")", "");
                            writeln!(dot, "  \"{}\" [shape=box, style=dotted, label=\"Missing\"];", ghost_id)?;
                            writeln!(dot, "  \"{}\" -> {} [style=dotted];", ghost_id, parent_node_id)?;
                        }
                    }
                }
            }

            writeln!(dot, "}}")?;
            Ok(dot)
        }
        */
        pub fn generate_graph_viz_simple(&self) -> anyhow::Result<String> {
            use std::fmt::Write;

            let mut dot = String::new();
            writeln!(dot, "digraph G {{")?;
            
            // 1. Graph Attributes
            writeln!(dot, "  rankdir=BT;")?;
            // ordering=in ensures that the order in which we define edges entering a node 
            // (the dependencies) is respected left-to-right.
            writeln!(dot, "  ordering=in;")?; 
            writeln!(dot, "  node [shape=box, fontname=\"Courier\", fontsize=10];")?;
            writeln!(dot, "  edge [color=\"black\"];")?;

            // 2. Define Nodes and Horizontal constraints (Invisible edges)
            for (level_idx, level_jobs) in self.jobs.iter().enumerate() {
                
                // We use a subgraph with rank=same to ensure all nodes 
                // at this level stay on the same horizontal timeline.
                writeln!(dot, "  subgraph level_{} {{", level_idx)?;
                writeln!(dot, "    rank=same;")?;

                for (job_index, job) in level_jobs.iter().enumerate() {
                    let node_id = format!("job_{}_{}", level_idx, job_index);

                    let label = if level_idx == 0 {
                        format!(
                            "Input Proof {}\nCheckpoint {}", 
                            job_index + 1, 
                            job.job_id.goal_id
                        )
                    } else {
                        let circuit_type_debug = format!("{:?}", job.job_id.circuit_type);
                        let display_type = circuit_type_debug.replace("ProvingJobCircuitType::", "");

                        format!(
                            "{}\nRewardLevel={}\nRewardIndex={}\nLayer={}",
                            display_type,
                            job.metadata.reward_tree_node_level,
                            job.metadata.reward_tree_node_index,
                            level_idx
                        )
                    };

                    writeln!(dot, "    {} [label=\"{}\"];", node_id, label)?;

                    // Horizontal Constraint:
                    // Force job_N to be to the left of job_N+1 using an invisible edge.
                    // This prevents "ragged" inputs from floating to the wrong side.
                    if job_index > 0 {
                        let prev_node_id = format!("job_{}_{}", level_idx, job_index - 1);
                        writeln!(dot, "    {} -> {} [style=invis, weight=2];", prev_node_id, node_id)?;
                    }
                }
                writeln!(dot, "  }}")?; // End subgraph
            }

            // 3. Define Logic Edges (Dependencies)
            // We do this in a separate pass or block to ensure the nodes are already placed in ranks.
            for (level_idx, level_jobs) in self.jobs.iter().enumerate() {
                for (job_index, job) in level_jobs.iter().enumerate() {
                    let node_id = format!("job_{}_{}", level_idx, job_index);

                    for dep_job_id in &job.metadata.dependencies {
                        if let Ok((dep_level, dep_index, _)) = self.get_job_level_index_by_id(dep_job_id) {
                            let child_node_id = format!("job_{}_{}", dep_level, dep_index);
                            writeln!(dot, "  {} -> {};", child_node_id, node_id)?;
                        } else {
                            let missing_id = format!("missing_{}_{}", level_idx, job_index);
                            writeln!(dot, "  {} [label=\"Missing\" style=dotted];", missing_id)?;
                            writeln!(dot, "  {} -> {} [style=dotted];", missing_id, node_id)?;
                        }
                    }
                }
            }

            writeln!(dot, "}}")?;
            Ok(dot)
        }
    }
    fn gen_random_checkpoint() -> (
        Hash,
        PQEDCheckpointLeaf<F, Hash>,
        PQEDCheckpointLeafStats<F, Hash>,
        PQEDCheckpointGlobalStateRoots<Hash>,
        PQEDCheckpointLeafCompact<Hash>,
    ) {
        let stats = PQEDCheckpointLeafStats::<F, Hash> {
            guta_fees_collected: F::from_u64_value(u64::qp_rand_gen()),
            da_fees_collected: F::from_u64_value(u64::qp_rand_gen()),
            user_ops_processed: F::from_u64_value(u64::qp_rand_gen()),
            total_transactions: F::from_u64_value(u64::qp_rand_gen()),
            slots_modified: F::from_u64_value(u64::qp_rand_gen()),
            pm_jobs_completed: PPMJobsCompletedStats {
                deploy_contracts_completed: F::from_u64_value(u64::qp_rand_gen()),
                register_users_completed: F::from_u64_value(u64::qp_rand_gen()),
                gutas_completed: F::from_u64_value(u64::qp_rand_gen()),
            },
            block_time: F::from_u64_value(u64::qp_rand_gen()),
            random_seed: Hash::rand(),
            pm_rewards_commitment: PPMRewardCommitment {
                register_users_root: Hash::rand(),
                gutas_root: Hash::rand(),
                deploy_contracts_root: Hash::rand(),
            },
            da_challenges_claimed: [F::ZERO_VALUE; 14],
        };
        let stats_hash = stats.qfhash::<Hasher>();
        let checkpoint_global_state_roots = PQEDCheckpointGlobalStateRoots::<Hash> {
            contract_tree_root: Hash::rand(),
            deposit_tree_root: Hash::rand(),
            user_tree_root: Hash::rand(),
            withdrawal_tree_root: Hash::rand(),
            user_registration_tree_root: Hash::rand(),
            validator_tree_root: Hash::ZERO,
        };
        let global_chain_root = checkpoint_global_state_roots.qfhash::<Hasher>();
        let checkpoint_leaf = PQEDCheckpointLeaf {
            global_chain_root,
            stats: stats.clone(),
        };
        let checkpoint_leaf_compact = PQEDCheckpointLeafCompact {
            global_chain_root,
            stats_hash,
        };
        let checkpoint_leaf_hash = checkpoint_leaf.qfhash::<Hasher>();
        (
            checkpoint_leaf_hash,
            checkpoint_leaf,
            stats,
            checkpoint_global_state_roots,
            checkpoint_leaf_compact,
        )
    }

    fn gen_job_for_index_checkpoint(
        checkpoint_id: u64,
        index: u64,
        checkpoint_tree_root: Hash,
    ) -> GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash> {
        GlobalUserTreeAggregatorHeaderWithTagValueAndJobID {
            header: GlobalUserTreeAggregatorHeaderWithTagValue {
                header: GlobalUserTreeAggregatorHeader {
                    guta_circuit_whitelist: Hash::from_values(1, 2, 3, 4),
                    checkpoint_tree_root,
                    state_transition: SubTreeNodeStateTransition {
                        old_node_value: Hasher::get_zero_hash(0),
                        new_node_value: Hash::rand(),
                        node_index: F::from_u64_value(index),
                        node_level: F::from_u8_value(REALM_LEVEL_U8),
                    },
                    stats: GUTAStats {
                        guta_fees_collected: F::from_u64_value(u64::qp_rand_gen()),
                        da_fees_collected: F::from_u64_value(u64::qp_rand_gen()),
                        user_ops_processed: F::from_u64_value(u64::qp_rand_gen()),
                        total_transactions: F::from_u64_value(u64::qp_rand_gen()),
                        slots_modified: F::from_u64_value(u64::qp_rand_gen()),
                    },
                    total_aggregation_proofs_generated: F::from_u8_value(0),
                },
                new_tag_tree_node_value: Hash::rand(),
            },
            job_id: QProvingJobDataID::new(
                QJobTopic::GenerateStandardProof,
                checkpoint_id,
                u32::qp_rand_gen(),
                u32::qp_rand_gen(),
                index as u32,
                ProvingJobCircuitType::GUTATwoEndCap,
                ProvingJobDataType::StandardProof,
                0,
            ),
        }
    }

    fn fixed_header(
        node_index: u64,
        old_node_value: Hash,
        new_node_value: Hash,
    ) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: Hash::from_values(1, 2, 3, 4),
            checkpoint_tree_root: Hash::from_values(5, 6, 7, 8),
            state_transition: SubTreeNodeStateTransition {
                old_node_value,
                new_node_value,
                node_index: F::from_u64_value(node_index),
                node_level: F::ZERO_VALUE,
            },
            stats: GUTAStats {
                guta_fees_collected: F::ZERO_VALUE,
                da_fees_collected: F::ZERO_VALUE,
                user_ops_processed: F::ZERO_VALUE,
                total_transactions: F::ZERO_VALUE,
                slots_modified: F::ZERO_VALUE,
            },
            total_aggregation_proofs_generated: F::from_u8_value(1),
        }
    }

    #[test]
    fn rejects_stale_leaf_update_before_mutation() {
        let tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(4);
        let stale_header = fixed_header(
            3,
            Hash::from_values(10, 11, 12, 13),
            Hash::from_values(20, 21, 22, 23),
        );

        let err = CoordinatorGUTAPlanner::<F, Hash>::ensure_input_leaf_matches_global_tree::<Hasher>(
            &tree,
            &stale_header,
            &[],
        )
        .unwrap_err();

        assert!(err.to_string().contains("stale GUTA update"));
        assert_eq!(tree.get_e_leaf_value(3), Hasher::get_zero_hash(0));
    }

    #[test]
    fn accepts_second_update_against_pending_first_update() {
        let tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(4);
        let first_new_value = Hash::from_values(20, 21, 22, 23);
        let second_header = fixed_header(3, first_new_value, Hash::from_values(30, 31, 32, 33));
        let pending_updates = [(3, first_new_value)];

        CoordinatorGUTAPlanner::<F, Hash>::ensure_input_leaf_matches_global_tree::<Hasher>(
            &tree,
            &second_header,
            &pending_updates,
        )
        .unwrap();
    }

    fn gen_rand_unique_array_of_u64s_in_range(len: usize, range_start: u64, range_end: u64) -> Vec<u64> {
        if len as u64 > (range_end - range_start) {
            panic!("Cannot generate {} unique values in range {}..{}", len, range_start, range_end);
        }
        use std::collections::HashSet;
        let mut set = HashSet::new();
        let mut rng = rand::thread_rng();
        while set.len() < len {
            let val = rng.gen_range(range_start..range_end);
            set.insert(val);
        }
        set.into_iter().collect()
    }
    fn get_job_metadata_for_input_jobs(input_jobs: &[GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash>]) -> Vec<PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>> {
        input_jobs
            .iter()
            .map(|job_header_with_id| {
                GlobalUserTreeAggregatorHeaderWithJobId {
                    header: job_header_with_id.header.header.clone(),
                    job_id: job_header_with_id.job_id.clone(),
                }.to_metadata_with_job_standard_children::<Hasher>(vec![])
            })
            .collect()
    }

    async fn test_n_jobs(input_jobs_count: usize) -> anyhow::Result<()> {
        let realm_identifier = QRealmIdentifier {
            realm_id: 1,
            realm_sub_id: 0,
        };
        let temp_store = Arc::new(InMemoryTempStore::new("coordinator-guta-planner-test".to_string(), 1, 0));
        let unique_pending_id = 0u64;
        let global_user_tree_height = REALM_LEVEL_U8;
        let checkpoint_tree = PsyDashMemoryAppendOnlyMerkleStore::<Hasher, Hash>::new(32);
        let mut global_user_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(global_user_tree_height);

        let (checkpoint_0_leaf_hash, _, _stats_0, _global_state_roots_0, _checkpoint_0_leaf_compact) = gen_random_checkpoint();
        checkpoint_tree.append_leaf(0, checkpoint_0_leaf_hash)?;

        let checkpoint_0_root = checkpoint_tree.get_root();
        let (checkpoint_1_leaf_hash, _, stats_1, global_state_roots_1, _checkpoint_1_leaf_compact) = gen_random_checkpoint();
        checkpoint_tree.append_leaf(1, checkpoint_1_leaf_hash)?;
        let checkpoint_1_root = checkpoint_tree.get_root();

        let jobs = gen_rand_unique_array_of_u64s_in_range(input_jobs_count, 0, 1u64 << REALM_LEVEL_U8)
            .into_iter()
            .map(|index| {
                if (u8::qp_rand_gen() & 1) == 1 {
                    gen_job_for_index_checkpoint(1, index, checkpoint_1_root)
                } else {
                    gen_job_for_index_checkpoint(0, index, checkpoint_0_root)
                }
            })
            .collect::<Vec<_>>();
        let total_input_jobs = jobs.len();

        let mut timer = DebugTimer::new("CoordinatorGUTAPlanner Test");
        let mut planner = CoordinatorGUTAPlanner::<F, Hash>::new(checkpoint_1_root);
        for job in &jobs {
            planner
                .add_realm_job::<Hasher, InMemoryTempStore>(
                    unique_pending_id,
                    &checkpoint_1_root,
                    &checkpoint_tree,
                    &mut global_user_tree,
                    temp_store.clone(),
                    job.clone(),
                )
                .await?;
        }
        timer.lap_batch("added realm jobs", "jobs", total_input_jobs);

        let current_checkpoint_root = checkpoint_1_root;
        let reward_tree_root_level = 2u8;
        let reward_tree_root_index = 0u64;
        let most_recent_checkpoint_global_state_roots = global_state_roots_1;
        let most_recent_checkpoint_stats_hash = stats_1.qfhash::<Hasher>();
        let guta_circuit_whitelist = Hash::from_values(1, 2, 3, 4);

        
        let (result, _, _) = planner
            .finalize_with_reward_ids(
                &realm_identifier,
                unique_pending_id,
                &current_checkpoint_root,
                &checkpoint_tree,
                &mut global_user_tree,
                temp_store.clone(),
                reward_tree_root_level,
                reward_tree_root_index,
                most_recent_checkpoint_global_state_roots,
                most_recent_checkpoint_stats_hash,
                guta_circuit_whitelist,
            )
            .await?;
        let expected_levels = if total_input_jobs <= 1 { 1 } else { log2_ceil(total_input_jobs) };
        if result.len() > expected_levels {
            return Err(anyhow::anyhow!(
                "Expected at most {} levels, got {} levels",
                expected_levels,
                result.len()
            ));
        }
        timer.lap_batch("finalized with reward ids", "jobs", total_input_jobs);
        
        let root_job_id = result
            .last()
            .and_then(|level| level.first())
            .map(|job_metadata| job_metadata.job_id.clone())
            .ok_or_else(|| anyhow::anyhow!("No root job generated"))?;
        // NOTE: finalize_with_reward_ids must only return the new jobs created, not the input jobs, as the return value are the jobs which are pushed to the worker queue
        let input_jobs_metadata = get_job_metadata_for_input_jobs(&jobs);
        
        let correctness_checker = JobCorrectnessChecker::new(input_jobs_metadata, result);
        println!("graph viz:\n{}", correctness_checker.generate_graph_viz_simple()?);
        correctness_checker.check_jobs_correctness::<Hasher>()?;
        correctness_checker.process_job_witness::<InMemoryTempStore>(&realm_identifier, unique_pending_id, temp_store.clone(), root_job_id, guta_circuit_whitelist).await?;
        

        Ok(())
    }
    #[tokio::test]
    async fn demonstration_of_basic_functionality_you_need_to_make_tests() {
        let mut has_error = false;
        for i in 1999..2000 {
            println!("Testing with {} input jobs...", i);
            let result = test_n_jobs(i).await;
            if result.is_err() {
                has_error = true;
                println!("Test failed: {:?}", result.err());
            }
        }
        if has_error {
            panic!("Some tests failed, see output above.");
        }
    }
    #[tokio::test]
    async fn demonstration_of_basic_functionality_you_need_to_make_tests_perf() {
        let mut has_error = false;
            let result = test_n_jobs(4096).await;
            if result.is_err() {
                has_error = true;
                println!("Test failed: {:?}", result.err());
            }
        
        if has_error {
            panic!("Some tests failed, see output above.");
        }
    }
}
