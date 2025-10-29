use parth_core::crypto::hash::traits::{MerkleHasher, ZeroableHash};

use crate::{agg::{AggStateTrackableInput, AggStateTransitionInput}, tree_planner::{BinaryTreeJob, BinaryTreePlanner}};


pub trait TPLeafAggregator<IL, IO> {
    fn get_output_from_inputs(left: &IO, right: &IO) -> IO;
    fn get_output_from_left_leaf(left: &IL, right: &IO) -> IO;
    fn get_output_from_right_leaf(left: &IO, right: &IL) -> IO;
    fn get_output_from_leaves(left: &IL, right: &IL) -> IO;
}

pub struct AggWTLeafAggregator;

impl<Hash: ZeroableHash + Copy, IL: AggStateTrackableInput<Hash>> TPLeafAggregator<IL, AggStateTransitionInput<Hash>>
    for AggWTLeafAggregator
{
    fn get_output_from_inputs(
        left: &AggStateTransitionInput<Hash>,
        right: &AggStateTransitionInput<Hash>,
    ) -> AggStateTransitionInput<Hash> {
        AggStateTransitionInput {
            left_input: left.condense(),
            right_input: right.condense(),
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        }
    }

    fn get_output_from_left_leaf(
        left: &IL,
        right: &AggStateTransitionInput<Hash>,
    ) -> AggStateTransitionInput<Hash> {
        right.combine_with_left_leaf(left)
    }

    fn get_output_from_right_leaf(
        left: &AggStateTransitionInput<Hash>,
        right: &IL,
    ) -> AggStateTransitionInput<Hash> {
        left.combine_with_right_leaf(right)
    }

    fn get_output_from_leaves(left: &IL, right: &IL) -> AggStateTransitionInput<Hash> {
        AggStateTransitionInput {
            left_input: left.get_state_transition(),
            right_input: right.get_state_transition(),
            left_proof_is_leaf: true,
            right_proof_is_leaf: true,
        }
    }
}



#[pderive::serialize_copy]
pub struct TPAltCircuitFingerprintConfig<Hash> {
    pub leaf_fingerprint: Hash,
    pub aggregator_fingerprint: Hash,
    pub dummy_fingerprint: Hash,
    pub verifier_data_cap_height: usize,
}

#[pderive::serialize_copy]
pub struct TPCircuitFingerprintConfig<Hash> {
    pub leaf_fingerprint: Hash,
    pub aggregator_fingerprint: Hash,
    pub dummy_fingerprint: Hash,
    pub allowed_circuit_hashes_root: Hash,
    pub leaf_circuit_type: u8,
    pub aggregator_circuit_type: u8,
}

impl<Hash> TPCircuitFingerprintConfig<Hash> {
    pub fn from_leaf_and_agg_fingerprints<Hasher: MerkleHasher<Hash>>(
        leaf_fingerprint: Hash,
        aggregator_fingerprint: Hash,
        dummy_fingerprint: Hash,
    ) -> Self {
        let allowed_circuit_hashes_root =
            Hasher::two_to_one(&leaf_fingerprint, &aggregator_fingerprint);
        Self {
            leaf_fingerprint,
            aggregator_fingerprint,
            dummy_fingerprint,
            allowed_circuit_hashes_root,
            leaf_circuit_type: 255,
            aggregator_circuit_type: 255,
        }
    }
    pub fn from_leaf_and_agg_fingerprints_with_type<Hasher: MerkleHasher<Hash>>(
        leaf_fingerprint: Hash,
        aggregator_fingerprint: Hash,
        dummy_fingerprint: Hash,
        leaf_circuit_type: u8,
        aggregator_circuit_type: u8,
    ) -> Self {
        let allowed_circuit_hashes_root =
            Hasher::two_to_one(&leaf_fingerprint, &aggregator_fingerprint);
        Self {
            leaf_fingerprint,
            aggregator_fingerprint,
            dummy_fingerprint,
            allowed_circuit_hashes_root,
            leaf_circuit_type,
            aggregator_circuit_type,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TreeAggJob<IO: Clone> {
    pub input: IO,
    pub tree_position: BinaryTreeJob,
}
impl<IO: Clone> TreeAggJob<IO> {
    pub fn new(input: IO, tree_position: BinaryTreeJob) -> Self {
        Self {
            input,
            tree_position,
        }
    }
}

pub fn generate_tree_inputs_with_position<LA: TPLeafAggregator<IL, IO>, IL: Clone, IO: Clone>(
    leaf_inputs: &[IL],
) -> Vec<Vec<TreeAggJob<IO>>> {
    let tree_positions = BinaryTreePlanner::new(leaf_inputs.len()).levels;

    let mut output: Vec<Vec<TreeAggJob<IO>>> = Vec::with_capacity(tree_positions.len());
    for level in tree_positions {
        let mut level_output: Vec<TreeAggJob<IO>> = Vec::with_capacity(level.len());
        for job in level {
            let input = if job.left_job.is_leaf() {
                if job.right_job.is_leaf() {
                    LA::get_output_from_leaves(
                        &leaf_inputs[job.left_job.index as usize],
                        &leaf_inputs[job.right_job.index as usize],
                    )
                } else {
                    LA::get_output_from_left_leaf(
                        &leaf_inputs[job.left_job.index as usize],
                        &output[job.right_job.level as usize - 1][job.right_job.index as usize]
                            .input,
                    )
                }
            } else {
                if job.right_job.is_leaf() {
                    LA::get_output_from_right_leaf(
                        &output[job.left_job.level as usize - 1][job.left_job.index as usize].input,
                        &leaf_inputs[job.right_job.index as usize],
                    )
                } else {
                    LA::get_output_from_inputs(
                        &output[job.left_job.level as usize - 1][job.left_job.index as usize].input,
                        &output[job.right_job.level as usize - 1][job.right_job.index as usize]
                            .input,
                    )
                }
            };
            level_output.push(TreeAggJob {
                input,
                tree_position: job,
            });
        }
        output.push(level_output);
    }

    output
}

pub fn generate_tree_inputs_from_leaves<LA: TPLeafAggregator<IL, IO>, IL: Clone, IO: Clone>(
    leaf_inputs: &[IL],
) -> Vec<Vec<IO>> {
    let tree_positions = BinaryTreePlanner::new(leaf_inputs.len()).levels;
    let mut output: Vec<Vec<IO>> = Vec::with_capacity(tree_positions.len());
    for level in tree_positions {
        let mut level_output: Vec<IO> = Vec::with_capacity(level.len());
        for job in level {
            let input = if job.left_job.is_leaf() {
                if job.right_job.is_leaf() {
                    LA::get_output_from_leaves(
                        &leaf_inputs[job.left_job.index as usize],
                        &leaf_inputs[job.right_job.index as usize],
                    )
                } else {
                    LA::get_output_from_left_leaf(
                        &leaf_inputs[job.left_job.index as usize],
                        &output[job.right_job.level as usize - 1][job.right_job.index as usize],
                    )
                }
            } else {
                if job.right_job.is_leaf() {
                    LA::get_output_from_right_leaf(
                        &output[job.left_job.level as usize - 1][job.left_job.index as usize],
                        &leaf_inputs[job.right_job.index as usize],
                    )
                } else {
                    LA::get_output_from_inputs(
                        &output[job.left_job.level as usize - 1][job.left_job.index as usize],
                        &output[job.right_job.level as usize - 1][job.right_job.index as usize],
                    )
                }
            };
            level_output.push(input);
        }
        output.push(level_output);
    }

    output
}
