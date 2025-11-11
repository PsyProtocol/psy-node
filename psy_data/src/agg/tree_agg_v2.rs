use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleZeroHasher, PCircuitWitness}, data::hash::merkle_node_key::SimpleMerkleNodeKey, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_serialize::{PsyCanonicalDatabaseSerializeBaseSingle, PsySerializeCanonicalAsyncSafe};

use crate::{agg::{AggStateTransitionInputV2, AggStateWitnessV2, DummyAggStateTransition}, worker::{metadata::{PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN, PsyProvingJobMetadata}, metadata_with_job_id::PsyProvingJobMetadataWithJobId}};

pub trait BasicTreePlannerHelper<JobId, Hash, LeafWitness, AggWitness, DummyWitness> {
    fn get_dummy_job_id(unique_checkpoint_id: u64) -> JobId;
    fn get_agg_job_id(unique_checkpoint_id: u64, node_key: SimpleMerkleNodeKey) -> JobId;
    fn get_leaf_job_id(unique_checkpoint_id: u64, node_key: SimpleMerkleNodeKey) -> JobId;
    fn create_dummy_witness(allowed_circuit_hashes_root: Hash, tree_root: Hash) -> DummyWitness;
    fn create_agg_two_leaf_witness(left: &LeafWitness, right: &LeafWitness) -> AggWitness;
    fn create_agg_left_leaf_right_agg_witness(left: &LeafWitness, right: &AggWitness) -> AggWitness;
    fn create_agg_left_agg_right_leaf_witness(left: &AggWitness, right: &LeafWitness) -> AggWitness;
    fn create_agg_to_agg_witness(left: &AggWitness, right: &AggWitness) -> AggWitness;
}

/*


pub const PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD: u8 = 0;
pub const PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN: u8 = 1;
pub const PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD: u8 = 2;
pub const PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD: u8 = 3;

#[pderive::serialize_clone_hash_job_id_ts]
#[ts(export, concrete(Hash = parth_core::PHash, JobId = QProvingJobDataID))]
#[repr(C)]
pub struct PsyProvingJobMetadata<Hash, JobId> {
    pub expected_public_inputs_hash: Hash,
    pub reward_tree_node_index: u64,
    pub reward_tree_node_level: u8,
    pub reward_tree_hash_mode: u8,      // How to hash this node's children when computing the reward tree hash
    pub reward_tree_node_children: u16, // Number of children this node has in the reward tree, used to hint at how to hash
    pub dependencies: Vec<JobId>,
}


*/

fn plan_jobs_for_tree_agg_old<
    JobId: Copy,
    F: QFelt64,
    Hash: QFHashBase<F> + Q256BitHash,
    Hasher: FieldQHasher<F, Hash>,
    LeafWitness: PCircuitWitness<F, Hash> + PsySerializeCanonicalAsyncSafe,
    PlannerHelper: BasicTreePlannerHelper<JobId, Hash, LeafWitness, AggStateTransitionInputV2<Hash>, DummyAggStateTransition<Hash>>,
>(
    unique_checkpoint_id: u64,
    start_tree_root: Hash,
    allowed_circuit_hashes_root: Hash,
    leaves: &[LeafWitness],
) -> anyhow::Result<(Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>>, Vec<(JobId, Vec<u8>)>)> {
    if leaves.len() == 0{
        let dummy_job_id = PlannerHelper::get_dummy_job_id(unique_checkpoint_id);
        let dummy_witness = PlannerHelper::create_dummy_witness(allowed_circuit_hashes_root, start_tree_root);
        let metadata = PsyProvingJobMetadata {
            expected_public_inputs_hash: dummy_witness.get_expected_public_inputs_hash::<Hasher>(),
            reward_tree_node_index: 0,
            reward_tree_node_level: 0,
            reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
            reward_tree_node_children: 0,
            dependencies: vec![]
        };
        let queue_item = PsyProvingJobMetadataWithJobId{
            job_id: dummy_job_id,
            metadata,
        };
        let dummy_witness_bytes = dummy_witness.psy_ser_into_bytes_vec()?;
        return Ok((
            vec![vec![queue_item]],
            vec![(dummy_job_id, dummy_witness_bytes)]
        ))
    }


    /*
    
    
     */



    todo!()
}


use anyhow::{anyhow, Result};

#[derive(Debug)]
enum Wit<'a, Hash, LeafWitness> {
    Leaf(&'a LeafWitness),
    Agg(AggStateTransitionInputV2<Hash>),
}

fn compute_max_level(mut num: usize) -> u8 {
    let mut h = 0u8;
    while num > 1 {
        num = (num + 1) / 2;
        h += 1;
    }
    h
}

fn build_subtree<'a, JobId: Copy, F: QFelt64, Hash: QFHashBase<F> + Q256BitHash, Hasher: FieldQHasher<F, Hash>, LeafWitness: PCircuitWitness<F, Hash> + PsySerializeCanonicalAsyncSafe, PlannerHelper: BasicTreePlannerHelper<JobId, Hash, LeafWitness, AggStateTransitionInputV2<Hash>, DummyAggStateTransition<Hash>>>(
    start: usize,
    num: usize,
    level: u8,
    index: u64,
    leaves: &'a [LeafWitness],
    unique_checkpoint_id: u64,
    allowed_circuit_hashes_root: Hash,
    layers: &mut Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>>,
    all_witnesses: &mut Vec<(JobId, Vec<u8>)>,
    max_level: u8,
) -> Result<(JobId, Wit<'a, Hash, LeafWitness>)> {
    let node_key = SimpleMerkleNodeKey { level, index };
    let mut deps = vec![];
    let mut hash_mode: u8 = 0;
    let mut num_children: u16 = 0;
    let mut job_id: JobId;
    let wit: Wit<'a, Hash, LeafWitness>;

    if num == 1 {
        let leaf_wit = &leaves[start];
        job_id = PlannerHelper::get_leaf_job_id(unique_checkpoint_id, node_key);
        hash_mode = PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN;
        num_children = 0;
        wit = Wit::Leaf(leaf_wit);
    } else {
        let left_num = (num + 1) / 2;
        let right_num = num / 2;
        let child_level = level.checked_add(1).ok_or(anyhow!("level overflow"))?;
        let left_index = index.checked_mul(2).ok_or(anyhow!("index overflow"))?;
        let right_index = left_index.checked_add(1).ok_or(anyhow!("index overflow"))?;

        let (left_id, left_wit) = build_subtree::<JobId, F, Hash, Hasher, LeafWitness, PlannerHelper>(start, left_num, child_level, left_index, leaves, unique_checkpoint_id, allowed_circuit_hashes_root, layers, all_witnesses, max_level)?;
        let (right_id, right_wit) = build_subtree::<JobId, F, Hash, Hasher, LeafWitness, PlannerHelper>(start + left_num, right_num, child_level, right_index, leaves, unique_checkpoint_id, allowed_circuit_hashes_root, layers, all_witnesses, max_level)?;

        deps = vec![left_id, right_id];
        let agg_wit = match (left_wit, right_wit) {
            (Wit::Leaf(l), Wit::Leaf(r)) => PlannerHelper::create_agg_two_leaf_witness(l, r),
            (Wit::Leaf(l), Wit::Agg(r)) => PlannerHelper::create_agg_left_leaf_right_agg_witness(l, &r),
            (Wit::Agg(l), Wit::Leaf(r)) => PlannerHelper::create_agg_left_agg_right_leaf_witness(&l, r),
            (Wit::Agg(l), Wit::Agg(r)) => PlannerHelper::create_agg_to_agg_witness(&l, &r),
        };
        wit = Wit::Agg(agg_wit);
        job_id = PlannerHelper::get_agg_job_id(unique_checkpoint_id, node_key);
        hash_mode = PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD;
        num_children = 2;
    }

    let expected_pi_hash = match &wit {
        Wit::Leaf(l) => l.get_expected_public_inputs_hash::<Hasher>(),
        Wit::Agg(a) => a.get_public_inputs_hash_no_tag_tree::<Hasher>(allowed_circuit_hashes_root),
    };

    let metadata = PsyProvingJobMetadata {
        expected_public_inputs_hash: expected_pi_hash,
        reward_tree_node_index: index,
        reward_tree_node_level: level,
        reward_tree_hash_mode: hash_mode,
        reward_tree_node_children: num_children,
        dependencies: deps,
    };

    let queue_item = PsyProvingJobMetadataWithJobId {
        job_id,
        metadata,
    };

    let layer_idx = (max_level - level) as usize;
    layers[layer_idx].push(queue_item);

    let witness_bytes = match &wit {
        Wit::Leaf(l) => l.psy_ser_to_bytes_vec()?,
        Wit::Agg(a) => a.psy_ser_to_bytes_vec()?,
    };
    all_witnesses.push((job_id, witness_bytes));

    Ok((job_id, wit))
}

pub fn plan_jobs_for_tree_agg<
    JobId: Copy,
    F: QFelt64,
    Hash: QFHashBase<F> + Q256BitHash,
    Hasher: FieldQHasher<F, Hash>,
    LeafWitness: PCircuitWitness<F, Hash> + PsySerializeCanonicalAsyncSafe,
    PlannerHelper: BasicTreePlannerHelper<JobId, Hash, LeafWitness, AggStateTransitionInputV2<Hash>, DummyAggStateTransition<Hash>>,
>(
    unique_checkpoint_id: u64,
    start_tree_root: Hash,
    allowed_circuit_hashes_root: Hash,
    leaves: &[LeafWitness],
) -> anyhow::Result<(Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>>, Vec<(JobId, Vec<u8>)>)> {
    if leaves.len() == 0{
        let dummy_job_id = PlannerHelper::get_dummy_job_id(unique_checkpoint_id);
        let dummy_witness = PlannerHelper::create_dummy_witness(allowed_circuit_hashes_root, start_tree_root);
        let metadata = PsyProvingJobMetadata {
            expected_public_inputs_hash: dummy_witness.get_expected_public_inputs_hash::<Hasher>(),
            reward_tree_node_index: 0,
            reward_tree_node_level: 0,
            reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
            reward_tree_node_children: 0,
            dependencies: vec![]
        };
        let queue_item = PsyProvingJobMetadataWithJobId{
            job_id: dummy_job_id,
            metadata,
        };
        let dummy_witness_bytes = dummy_witness.psy_ser_into_bytes_vec()?;
        return Ok((
            vec![vec![queue_item]],
            vec![(dummy_job_id, dummy_witness_bytes)]
        ))
    }

    let max_level = compute_max_level(leaves.len());
    let mut layers: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>> = vec![vec![]; (max_level as usize) + 1];
    let mut all_witnesses: Vec<(JobId, Vec<u8>)> = vec![];

    let _ = build_subtree::<JobId, F, Hash, Hasher, LeafWitness, PlannerHelper>(0, leaves.len(), 0, 0, leaves, unique_checkpoint_id, allowed_circuit_hashes_root, &mut layers, &mut all_witnesses, max_level)?;

    Ok((layers, all_witnesses))
}

