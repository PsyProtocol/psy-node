use std::{collections::HashMap, sync::Arc};

use parth_common::memory_stores::{dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, mem_tree_recorder::SimpleMemoryMerkleRecorderStore};
use parth_core::{
    crypto::hash::traits::{FieldQHasher, QFieldHashable},
    felt::QFelt64,
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    guta::header_extended::{GlobalUserTreeAggregatorHeaderWithJobId, GlobalUserTreeAggregatorHeaderWithTagValueAndJobID}, proof_input::guta::{
        GUTANoChangeFullInput, GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput, GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInputResolver, GUTAVerifyTwoGUTACircuitInputV2, GUTAVerifyTwoGUTALinearCircuitInput, GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput, GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2, VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple
    }, v1::qdata::checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeafCompact, PQEDCheckpointLeafCompactWithStateRoots, PQEDCheckpointLeafStats}, worker::{
        metadata::{PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN, PsyProvingJobMetadata},
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    }
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::psy_temp_db::StandardProcessorTempDBStoreBase;

const MAX_COORDINATOR_HEIGHT: usize = 24;
pub struct CoordinatorGUTAPlanner<F, Hash> {
    pub job_witnesses: Vec<(QProvingJobDataID, Vec<u8>)>,
    pub job_levels: [Vec<PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>>; MAX_COORDINATOR_HEIGHT],
    pub job_guta_headers: [Vec<GlobalUserTreeAggregatorHeaderWithJobId<F, Hash>>; MAX_COORDINATOR_HEIGHT],
    pub job_count: usize,
}
pub trait CoordinatorTagTreeHelper<Hash> {
    async fn set_reward_tree_tags(&mut self, realm_identifier: &QRealmIdentifier, unique_pending_id: u64, tags: ()) -> anyhow::Result<()>;
}
impl<F, Hash> CoordinatorGUTAPlanner<F, Hash> {
    pub fn new() -> Self {
        Self {
            job_witnesses: Vec::new(),
            job_levels: core::array::from_fn(|_| Vec::new()),
            job_guta_headers: core::array::from_fn(|_| Vec::new()),
            job_count: 0,
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash + QFHashBase<F>> CoordinatorGUTAPlanner<F, Hash> {
    pub fn add_witness(&mut self, job_id: QProvingJobDataID, witness: Vec<u8>) {
        self.job_witnesses.push((job_id, witness));
    }
    pub fn add_job_to_level_two_children<Hasher: FieldQHasher<F, Hash>>(
        &mut self,
        unique_pending_id: u64,
        current_checkpoint_root: &Hash,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        level: usize,
        left_child_level: usize,
        left_child_index: usize,
        right_child_level: usize,
        right_child_index: usize,
    ) -> anyhow::Result<()> {
        if level >= MAX_COORDINATOR_HEIGHT {
            return Err(anyhow::anyhow!(
                "Level {} exceeds maximum coordinator height {}",
                level,
                MAX_COORDINATOR_HEIGHT
            ));
        }
        let index = self.job_levels[level - 1].len() as u64;

        let left_child = &self.job_guta_headers[left_child_level][left_child_index];
        let right_child = &self.job_guta_headers[right_child_level][right_child_index];

        let left_needs_dmp = left_child.header.state_transition.node_level != F::ZERO_VALUE;
        let right_needs_dmp = right_child.header.state_transition.node_level != F::ZERO_VALUE;
        let left_needs_checkpoint_update = &left_child.header.checkpoint_tree_root != current_checkpoint_root;
        let right_needs_checkpoint_update = &right_child.header.checkpoint_tree_root != current_checkpoint_root;

        let (witness_bytes, guta_header) = if left_needs_dmp {
            if !right_needs_dmp {
                anyhow::bail!("Left child needs DMP but right child does not, which is unsupported");
            }
            let left_global_user_tree_delta_merkle_proof = global_user_tree.set_leaf(
                left_child.header.state_transition.node_index.to_u64_value(),
                left_child.header.state_transition.new_node_value,
            );
            let right_global_user_tree_delta_merkle_proof = global_user_tree.set_leaf(
                right_child.header.state_transition.node_index.to_u64_value(),
                right_child.header.state_transition.new_node_value,
            );
            if left_needs_checkpoint_update || right_needs_checkpoint_update {
                let witness = GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2 {
                    left_header: left_child.header,
                    left_global_user_tree_delta_merkle_proof,
                    left_historical_checkpoint_merkle_proof: checkpoint_tree
                        .get_historical_append_only_merkle_proof_for_root(left_child.header.checkpoint_tree_root)?,
                    right_header: right_child.header,
                    right_global_user_tree_delta_merkle_proof,
                    right_historical_checkpoint_merkle_proof: checkpoint_tree
                        .get_historical_append_only_merkle_proof_for_root(right_child.header.checkpoint_tree_root)?,
                };
                let new_guta_header = GlobalUserTreeAggregatorHeaderWithJobId {
                    header: witness.get_new_guta_header(),
                    job_id: QProvingJobDataID::new_proof_job_id(
                        unique_pending_id,
                        level as u32,
                        ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade,
                        0,
                        index as u32,
                    ),
                };
                let witness_bytes = witness.psy_ser_into_bytes_vec()?;
                (witness_bytes, new_guta_header)
            } else {
                let witness = GUTAVerifyTwoGUTACircuitInputV2 {
                    left_header: left_child.header,
                    left_global_user_tree_delta_merkle_proof,
                    right_header: right_child.header,
                    right_global_user_tree_delta_merkle_proof,
                };
                let new_guta_header = GlobalUserTreeAggregatorHeaderWithJobId {
                    header: witness.get_new_guta_header(),
                    job_id: QProvingJobDataID::new_proof_job_id(unique_pending_id, level as u32, ProvingJobCircuitType::GUTATwoGUTA, 0, index as u32),
                };
                let witness_bytes = witness.psy_ser_into_bytes_vec()?;
                (witness_bytes, new_guta_header)
            }
        } else if right_needs_dmp {
            let witness = GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput {
                left_header: left_child.header,
                right_header: right_child.header,
                right_global_user_tree_delta_merkle_proof: global_user_tree.set_leaf(
                    right_child.header.state_transition.node_index.to_u64_value(),
                    right_child.header.state_transition.new_node_value,
                ),
                right_historical_checkpoint_proof: checkpoint_tree
                    .get_historical_append_only_merkle_proof_for_root(right_child.header.checkpoint_tree_root)?,
            };
            let new_guta_header = GlobalUserTreeAggregatorHeaderWithJobId {
                header: witness.get_new_guta_header(),
                job_id: QProvingJobDataID::new_proof_job_id(
                    unique_pending_id,
                    level as u32,
                    ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint,
                    0,
                    index as u32,
                ),
            };
            let witness_bytes = witness.psy_ser_into_bytes_vec()?;
            (witness_bytes, new_guta_header)
        } else {
            if left_needs_checkpoint_update || right_needs_checkpoint_update {
                let witness = GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput {
                    left_header: left_child.header,
                    right_header: right_child.header,
                    left_historical_checkpoint_proof: checkpoint_tree
                        .get_historical_append_only_merkle_proof_for_root(left_child.header.checkpoint_tree_root)?,
                    right_historical_checkpoint_proof: checkpoint_tree
                        .get_historical_append_only_merkle_proof_for_root(right_child.header.checkpoint_tree_root)?,
                };
                let new_guta_header = GlobalUserTreeAggregatorHeaderWithJobId {
                    header: witness.get_new_guta_header(),
                    job_id: QProvingJobDataID::new_proof_job_id(
                        unique_pending_id,
                        level as u32,
                        ProvingJobCircuitType::GUTATwoGUTALinearUpgradeCheckpoint,
                        0,
                        index as u32,
                    ),
                };
                let witness_bytes = witness.psy_ser_into_bytes_vec()?;
                (witness_bytes, new_guta_header)
            } else {
                let witness = GUTAVerifyTwoGUTALinearCircuitInput {
                    left_header: left_child.header,
                    right_header: right_child.header,
                };
                let new_guta_header = GlobalUserTreeAggregatorHeaderWithJobId {
                    header: witness.get_new_guta_header(),
                    job_id: QProvingJobDataID::new_proof_job_id(
                        unique_pending_id,
                        level as u32,
                        ProvingJobCircuitType::GUTATwoGUTALinear,
                        0,
                        index as u32,
                    ),
                };
                let witness_bytes = witness.psy_ser_into_bytes_vec()?;
                (witness_bytes, new_guta_header)
            }
        };

        let job_metadata_with_job_id = guta_header.to_metadata_with_job_standard_children::<Hasher>(vec![left_child.job_id, right_child.job_id]);
        self.job_witnesses.push((job_metadata_with_job_id.job_id, witness_bytes));
        self.job_guta_headers[level].push(guta_header);
        self.job_levels[level].push(job_metadata_with_job_id);
        self.job_count += 1;

        if index & 1 == 1 {
            // if its odd, we add a parent job to aggregate the two children
            self.add_job_to_level_two_children::<Hasher>(
                unique_pending_id,
                current_checkpoint_root,
                checkpoint_tree,
                global_user_tree,
                level + 1,
                level,
                index as usize - 1,
                level,
                index as usize,
            )?;
            if level == 1 {
                // clean up unnecesarry data from queue, these are realm submissions and don't
                // correspond to any "real" jobs
                self.job_guta_headers[level - 1].clear();
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
        job: &GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash>,
    ) -> anyhow::Result<()> {
        self.add_realm_job_inner(unique_pending_id, current_checkpoint_root, checkpoint_tree, global_user_tree, job)
    }
    pub fn add_realm_job_inner<Hasher: FieldQHasher<F, Hash>>(
        &mut self,
        unique_pending_id: u64,
        current_checkpoint_root: &Hash,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        job: &GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash>,
    ) -> anyhow::Result<()> {
        let header_with_job_id = GlobalUserTreeAggregatorHeaderWithJobId {
            header: job.header.header.clone(),
            job_id: job.job_id.clone(),
        };
        let index = self.job_levels[0].len() as u64;
        let mut job_metadata_with_job_id = header_with_job_id.to_metadata_with_job_standard_children::<Hasher>(vec![]);

        // HACK: mark the realm submission jobs as having no children and set the public
        // inputs hash to the new tag tree node value
        job_metadata_with_job_id.metadata.expected_public_inputs_hash = job.header.new_tag_tree_node_value;
        job_metadata_with_job_id.metadata.reward_tree_hash_mode = PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN;
        self.job_levels[0].push(job_metadata_with_job_id);
        if index & 1 == 1 {
            // if its odd, we add a parent job to aggregate the two children
            self.add_job_to_level_two_children::<Hasher>(
                unique_pending_id,
                current_checkpoint_root,
                checkpoint_tree,
                global_user_tree,
                1,
                0,
                (index - 1) as usize,
                0,
                index as usize,
            )?;
            // clean up unnecesarry data from queue, these are realm submissions and don't
            // correspond to any "real" jobs
            self.job_guta_headers[0].clear();
        }

        Ok(())
    }
    pub fn replace_job_parent_level_dependencies(&mut self, child_level: usize, new_job_id: QProvingJobDataID) -> anyhow::Result<()> {
        // this is hacky
        let parent_level = child_level + 1;
        if parent_level > MAX_COORDINATOR_HEIGHT {
            return Err(anyhow::anyhow!(
                "Parent level {} exceeds maximum coordinator height {}",
                parent_level,
                MAX_COORDINATOR_HEIGHT
            ));
        }
        let parent_level_index = self.job_levels[parent_level].len() - 1;
        let job_index = self.job_levels[parent_level][parent_level_index].metadata.dependencies.len()-1;
        self.job_levels[parent_level][parent_level_index].metadata.dependencies[job_index] = new_job_id;

        Ok(())
    }
    pub fn is_perfect_tree(&self) -> bool {
        for level in 0..(MAX_COORDINATOR_HEIGHT - 1) {
            if !self.job_levels[level].is_empty() {
                if self.job_levels[level].len() & 1 == 1 {
                    return false;
                }
            }
        }
        true
    }
    pub fn get_root_row(&self) -> usize {
        for level in (0..MAX_COORDINATOR_HEIGHT).rev() {
            if !self.job_levels[level].is_empty() {
                return level;
            }
        }
        0
    }
    pub fn find_job_level_and_index(&self, job_id: &QProvingJobDataID) -> Option<(usize, usize)> {
        for level in 0..MAX_COORDINATOR_HEIGHT {
            for (index, job_metadata) in self.job_levels[level].iter().enumerate() {
                if &job_metadata.job_id == job_id {
                    return Some((level, index));
                }
            }
        }
        None
    }

    pub fn update_reward_tree_config(&mut self, level: usize, index: usize, reward_tree_node_level: u8, reward_tree_node_index: u64) -> anyhow::Result<()> {
        if level >= MAX_COORDINATOR_HEIGHT {
            return Err(anyhow::anyhow!(
                "Level {} exceeds maximum coordinator height {}",
                level,
                MAX_COORDINATOR_HEIGHT
            ));
        }
        self.job_levels[level][index].metadata.reward_tree_node_level = reward_tree_node_level;
        self.job_levels[level][index].metadata.reward_tree_node_index = reward_tree_node_index;
        let deps = self.job_levels[level][index].metadata.dependencies.clone();
        for d in deps {
            let (child_level, child_index) = self.find_job_level_and_index(&d).ok_or_else(|| anyhow::anyhow!("Could not find child job id in planner"))?;
            self.update_reward_tree_config(child_level, child_index, reward_tree_node_level + 1, (reward_tree_node_index << 1) | (child_index as u64))?;
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
        if self.job_count == 0 {
            if self.job_guta_headers[0].len() == 1 {
                // handle case where there is only one realm job, so we need to verify to cap
                // and upgrade checkpoint
                let job = self.job_guta_headers[0].pop().unwrap();

                let witness = VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple {
                    guta_proof_header: job.header,
                    top_line_siblings: global_user_tree
                        .set_leaf(
                            job.header.state_transition.node_index.to_u64_value(),
                            job.header.state_transition.new_node_value,
                        )
                        .siblings,
                    historical_checkpoint_proof: checkpoint_tree.get_historical_append_only_merkle_proof_for_root(job.header.checkpoint_tree_root)?,
                    total_aggregation_proofs_generated: job.header.total_aggregation_proofs_generated,
                };
                let expected_public_inputs_hash = witness.get_public_inputs_hash_no_rewards_tag::<Hasher>();
                let new_job_id =
                    QProvingJobDataID::new_proof_job_id(unique_pending_id, 0, ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade, 0, 0);

                let witness_bytes = witness.psy_ser_into_bytes_vec()?;
                temp_store
                    .set_tdb_proof_witnesses_tuple_owned_raw(realm_identifier, unique_pending_id, vec![(new_job_id, witness_bytes)])
                    .await?;
                
                let metadata = PsyProvingJobMetadataWithJobId {
                    job_id: new_job_id,
                    metadata: PsyProvingJobMetadata {
                        expected_public_inputs_hash,
                        reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD,
                        reward_tree_node_index: reward_tree_root_index,
                        reward_tree_node_level: reward_tree_root_level,
                        reward_tree_node_children: 1,
                        dependencies: vec![job.job_id],
                    },
                };

                self.job_count = 1;
                return Ok(vec![vec![metadata]]);
            }else if self.job_guta_headers[0].is_empty() {
                
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

                let witness_bytes = no_change_input.psy_ser_into_bytes_vec()?;
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
            }else{
                anyhow::bail!("Multiple incomplete jobs in GUTA planner");
            }
        }else{
            // plan jobs normally, ensuring that the rows with an odd number of proofs are finalized correctly
            /*
            
                How should I modify my code to be able to support non perfect trees?
                Do I have to delay witness generation until the end?
             */
            if self.is_perfect_tree() {
                // perfect tree, we can finalize normally   
                // all of the witnesses are already generated
                let root_level = self.get_root_row();
                self.update_reward_tree_config(root_level, 0, reward_tree_root_level, reward_tree_root_index)?;
                let job_levels = self.job_levels;
                let witnesses = self.job_witnesses;
                temp_store
                    .set_tdb_proof_witnesses_tuple_owned_raw(realm_identifier, unique_pending_id, witnesses)
                    .await?;
                return Ok(job_levels.into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>())
            }

        }
        /*
        reward_tree_node_index: (reward_tree_root_index << level) | index,
        reward_tree_node_level: level + reward_tree_root_level,
        we need to 
        */
        self.job_count = self.job_witnesses.len();

        todo!()
    }
}
/*
Here is the CirciutType enum for reference:

#[derive(TS)]
#[ts(export)]
#[pderive::serialize_enum_repr_strum]
#[repr(u8)]
pub enum ProvingJobCircuitType {
    AppendUserRegistrationTree = 0,
    AppendUserRegistrationTreeAggregate = 1,

    AddL1Deposit = 2,
    AddL1DepositAggregate = 3,

    ClaimL1Deposit = 4,
    ClaimL1DepositAggregate = 5,

    UserEndCap = 6,
    GUTATwoEndCap = 7,
    GUTATwoGUTA = 8,
    GUTALeftEndCapRightGUTA = 9,
    GUTALeftGUTARightEndCap = 10,
    GUTASingleEndCap = 11,
    GUTARegisterUsers = 12,
    GUTAVerifyToCap = 13,
    GUTAOnlyRegisterUsers = 14,
    GUTANoChange = 15,

    AddL1Withdrawal = 16,
    AddL1WithdrawalAggregate = 17,

    BatchDeployContracts = 18,
    BatchDeployContractsAggregate = 19,

    ProcessL1Withdrawal = 20,
    ProcessL1WithdrawalAggregate = 21,

    GenerateRollupStateTransitionProof = 32,
    GenerateSigHashIntrospectionProof = 33,
    GenerateFinalSigHashProof = 34,
    GenerateFinalSigHashProofGroth16 = 35,
    WrapFinalSigHashProofBLS12381 = 36,
    GenesisBlockCheckpointStateTransition = 37,

    AggUserRegisterDeployContractsGUTA = 40,
    AggAddProcessL1WithdrawalAddL1Deposit = 41,

    DummyAppendUserRegistrationTreeAggregate = 48,
    DummyAddL1DepositAggregate = 49,
    DummyClaimL1DepositAggregate = 50,
    DummyGUTA = 51,
    DummyAddL1WithdrawalAggregate = 52,
    DummyProcessL1WithdrawalAggregate = 53,
    DummyBatchDeployContractsAggregate = 54,

    // ADDED NEW - For Historical Upgrades
    GUTATwoGUTAWithCheckpointUpgrade = 55,
    GUTAVerifyToCapWithCheckpointUpgrade = 56,

    // ADDED NEW - For Linear Transitions
    GUTATwoGUTALinear = 57,
    GUTATwoGUTALinearUpgradeCheckpoint = 58,
    GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint = 59,
    GUTAVerifyLeftLeafRightLinearUpgradeCheckpoint = 60,

    WrappedSignatureProof = 64,
    Secp256K1SignatureProof = 65,

    NotifyRealmComplete = 192,

    TypeA = 224,
    TypeB = 225,
    TypeC = 226,
    TypeD = 227,
    TypeE = 228,
    TypeF = 229,
    Invalid = 254,
    Unknown = 255,
}


And some other job witness types you can use:

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct GUTAVerifyTwoGUTALinearCircuitInput<F, Hash> {
    pub left_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub right_header: GlobalUserTreeAggregatorHeader<F, Hash>,
}
impl<F: QFelt, Hash: Copy> GUTAVerifyTwoGUTALinearCircuitInput<F, Hash> {
    pub fn get_guta_header_a(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.left_header
    }
    pub fn get_guta_header_b(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.right_header
    }
    pub fn get_new_guta_header(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.left_header.guta_circuit_whitelist,
            checkpoint_tree_root: self.left_header.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.left_header.state_transition.old_node_value,
                new_node_value: self.right_header.state_transition.new_node_value,
                node_index: self.left_header.state_transition.node_index,
                node_level: self.left_header.state_transition.node_level,
            },
            stats: self.left_header.stats.combine_with(&self.right_header.stats),
            total_aggregation_proofs_generated: self.left_header.total_aggregation_proofs_generated + self.right_header.total_aggregation_proofs_generated + F::from_u8_value(1),
        }
    }
}
impl<F: QFelt64, Hash: QFHashBase<F>> GUTAVerifyTwoGUTALinearCircuitInput<F, Hash> {
    pub fn get_public_inputs_hash_no_rewards_tag<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        let new_guta_header = self.get_new_guta_header();
        new_guta_header.qfhash::<Hasher>()
    }
}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput<F, Hash> {
    pub left_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub right_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub left_historical_checkpoint_proof: MerkleProofCore<Hash>,
    pub right_historical_checkpoint_proof: MerkleProofCore<Hash>,
}

impl<F: QFelt, Hash: Copy> GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput<F, Hash> {
    pub fn get_guta_header_a(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.left_header
    }
    pub fn get_guta_header_b(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.right_header
    }
    pub fn get_new_guta_header(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.left_header.guta_circuit_whitelist,
            checkpoint_tree_root: self.left_historical_checkpoint_proof.root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.left_header.state_transition.old_node_value,
                new_node_value: self.right_header.state_transition.new_node_value,
                node_index: self.left_header.state_transition.node_index,
                node_level: self.left_header.state_transition.node_level,
            },
            stats: self.left_header.stats.combine_with(&self.right_header.stats),
            total_aggregation_proofs_generated: self.left_header.total_aggregation_proofs_generated + self.right_header.total_aggregation_proofs_generated + F::from_u8_value(1),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput<F, Hash> {
    pub fn get_public_inputs_hash_no_rewards_tag<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        let new_guta_header = self.get_new_guta_header();
        new_guta_header.qfhash::<Hasher>()
    }
}
#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput<F, Hash> {
    pub left_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub right_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub right_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore<Hash>,
    pub right_historical_checkpoint_proof: MerkleProofCore<Hash>,
}

impl<F: QFelt, Hash: Copy> GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput<F, Hash> {
    pub fn get_guta_header_a(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.left_header
    }
    pub fn get_guta_header_b(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.right_header
    }
    pub fn get_new_guta_header(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.left_header.guta_circuit_whitelist,
            checkpoint_tree_root: self.left_header.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.left_header.state_transition.old_node_value,
                new_node_value: self.right_header.state_transition.new_node_value,
                node_index: self.left_header.state_transition.node_index,
                node_level: self.left_header.state_transition.node_level,
            },
            stats: self.left_header.stats.combine_with(&self.right_header.stats),
            total_aggregation_proofs_generated: self.left_header.total_aggregation_proofs_generated + self.right_header.total_aggregation_proofs_generated + F::from_u8_value(1),
        }
    }
}


impl<F: QFelt64, Hash: QFHashBase<F>> GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput<F, Hash> {
    pub fn get_public_inputs_hash_no_rewards_tag<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        let new_guta_header = self.get_new_guta_header();
        new_guta_header.qfhash::<Hasher>()
    }
}


*/


#[cfg(test)]
mod tests {


    type F = parth_core::PF;
    type Hash = parth_core::PHash;
    use super::*;

    #[test]
    fn demonstration_of_basic_functionality_you_need_to_make_tests() {
    }


}