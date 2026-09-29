use parth_core::{
    QJobIdBase, crypto::hash::traits::{FieldQHasher, PCircuitWitness}, data::hash::merkle_node_key::SimpleMerkleNodeKey, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}
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

fn build_subtree<'a, JobId: QJobIdBase, F: QFelt64, Hash: QFHashBase<F> + Q256BitHash, Hasher: FieldQHasher<F, Hash>, LeafWitness: PCircuitWitness<F, Hash> + PsySerializeCanonicalAsyncSafe, PlannerHelper: BasicTreePlannerHelper<JobId, Hash, LeafWitness, AggStateTransitionInputV2<Hash>, DummyAggStateTransition<Hash>>>(
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
    let hash_mode: u8;
    let num_children: u16;
    let job_id: JobId;
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

        deps = vec![left_id.output_proof_id(), right_id.output_proof_id()];
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
    JobId: QJobIdBase,
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
            job_id: dummy_job_id.output_proof_id(),
            metadata,
        };
        let dummy_witness_bytes = dummy_witness.psy_ser_into_bytes_vec()?;
        return Ok((
            vec![vec![queue_item]],
            vec![(dummy_job_id.input_witness_id(), dummy_witness_bytes)]
        ))
    }

    let max_level = compute_max_level(leaves.len());
    let mut layers: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>> = vec![vec![]; (max_level as usize) + 1];
    let mut all_witnesses: Vec<(JobId, Vec<u8>)> = vec![];

    let _ = build_subtree::<JobId, F, Hash, Hasher, LeafWitness, PlannerHelper>(0, leaves.len(), 0, 0, leaves, unique_checkpoint_id, allowed_circuit_hashes_root, &mut layers, &mut all_witnesses, max_level)?;

    Ok((layers, all_witnesses))
}






fn build_subtree_with_offset_root<'a, JobId: QJobIdBase, F: QFelt64, Hash: QFHashBase<F> + Q256BitHash, Hasher: FieldQHasher<F, Hash>, LeafWitness: PCircuitWitness<F, Hash> + PsySerializeCanonicalAsyncSafe, PlannerHelper: BasicTreePlannerHelper<JobId, Hash, LeafWitness, AggStateTransitionInputV2<Hash>, DummyAggStateTransition<Hash>>>(
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
    reward_tree_root_index: u64,
    reward_tree_root_level: u8,
) -> Result<(JobId, Wit<'a, Hash, LeafWitness>)> {
    let node_key = SimpleMerkleNodeKey { level, index };
    let mut deps = vec![];
    let hash_mode: u8;
    let num_children: u16;
    let job_id: JobId;
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

        let (left_id, left_wit) = build_subtree_with_offset_root::<JobId, F, Hash, Hasher, LeafWitness, PlannerHelper>(start, left_num, child_level, left_index, leaves, unique_checkpoint_id, allowed_circuit_hashes_root, layers, all_witnesses, max_level, reward_tree_root_index, reward_tree_root_level)?;
        let (right_id, right_wit) = build_subtree_with_offset_root::<JobId, F, Hash, Hasher, LeafWitness, PlannerHelper>(start + left_num, right_num, child_level, right_index, leaves, unique_checkpoint_id, allowed_circuit_hashes_root, layers, all_witnesses, max_level, reward_tree_root_index, reward_tree_root_level)?;

        deps = vec![left_id.output_proof_id(), right_id.output_proof_id()];
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
        reward_tree_node_index: (reward_tree_root_index << level) | index,
        reward_tree_node_level: level + reward_tree_root_level,
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



pub fn plan_jobs_for_tree_agg_offset_root<
    JobId: QJobIdBase,
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
    reward_tree_root_index: u64,
    reward_tree_root_level: u8,
) -> anyhow::Result<(Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>>, Vec<(JobId, Vec<u8>)>)> {
    if leaves.len() == 0{
        let dummy_job_id = PlannerHelper::get_dummy_job_id(unique_checkpoint_id);
        let dummy_witness = PlannerHelper::create_dummy_witness(allowed_circuit_hashes_root, start_tree_root);
        let metadata = PsyProvingJobMetadata {
            expected_public_inputs_hash: dummy_witness.get_expected_public_inputs_hash::<Hasher>(),
            reward_tree_node_index: reward_tree_root_index,
            reward_tree_node_level: reward_tree_root_level,
            reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
            reward_tree_node_children: 0,
            dependencies: vec![]
        };
        let queue_item = PsyProvingJobMetadataWithJobId{
            job_id: dummy_job_id.output_proof_id(),
            metadata,
        };
        let dummy_witness_bytes = dummy_witness.psy_ser_into_bytes_vec()?;
        return Ok((
            vec![vec![queue_item]],
            vec![(dummy_job_id.input_witness_id(), dummy_witness_bytes)]
        ))
    }

    let max_level = compute_max_level(leaves.len());
    let mut layers: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>> = vec![vec![]; (max_level as usize) + 1];
    let mut all_witnesses: Vec<(JobId, Vec<u8>)> = vec![];

    let _ = build_subtree_with_offset_root::<JobId, F, Hash, Hasher, LeafWitness, PlannerHelper>(0, leaves.len(), 0, 0, leaves, unique_checkpoint_id, allowed_circuit_hashes_root, &mut layers, &mut all_witnesses, max_level, reward_tree_root_index, reward_tree_root_level)?;

    Ok((layers, all_witnesses))
}

#[cfg(test)]
mod tests {
    use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
    use parth_core::pgoldilocks::{PoseidonHasher, QHashOut};
    use parth_core::PF;

    use super::*;
    use crate::agg::{AggStateTrackableInput, AggStateTransition, AggStateTransitionInput};

    type Hash = QHashOut<PF>;
    type Leaf = AggStateTransitionInput<Hash>;

    struct Helper;

    impl BasicTreePlannerHelper<QProvingJobDataID, Hash, Leaf, AggStateTransitionInputV2<Hash>, DummyAggStateTransition<Hash>> for Helper {
        fn get_dummy_job_id(checkpoint: u64) -> QProvingJobDataID {
            QProvingJobDataID::new_proof_job_id(checkpoint, 0, ProvingJobCircuitType::Unknown, 0, 0)
        }

        fn get_agg_job_id(checkpoint: u64, key: SimpleMerkleNodeKey) -> QProvingJobDataID {
            QProvingJobDataID::new_proof_job_id(checkpoint, key.level as u32, ProvingJobCircuitType::Unknown, 1, key.index as u32)
        }

        fn get_leaf_job_id(checkpoint: u64, key: SimpleMerkleNodeKey) -> QProvingJobDataID {
            QProvingJobDataID::new_proof_job_id(checkpoint, key.level as u32, ProvingJobCircuitType::Unknown, 2, key.index as u32)
        }

        fn create_dummy_witness(allowed: Hash, root: Hash) -> DummyAggStateTransition<Hash> {
            DummyAggStateTransition {
                unmodified_state_tree_root: root,
                allowed_circuit_hashes_root: allowed,
                is_deploy_contracts: false,
                is_register_users: false,
            }
        }

        fn create_agg_two_leaf_witness(left: &Leaf, right: &Leaf) -> AggStateTransitionInputV2<Hash> {
            aggregate(left.get_state_transition(), right.get_state_transition(), true, true)
        }

        fn create_agg_left_leaf_right_agg_witness(left: &Leaf, right: &AggStateTransitionInputV2<Hash>) -> AggStateTransitionInputV2<Hash> {
            aggregate(left.get_state_transition(), right.get_state_transition(), true, false)
        }

        fn create_agg_left_agg_right_leaf_witness(left: &AggStateTransitionInputV2<Hash>, right: &Leaf) -> AggStateTransitionInputV2<Hash> {
            aggregate(left.get_state_transition(), right.get_state_transition(), false, true)
        }

        fn create_agg_to_agg_witness(left: &AggStateTransitionInputV2<Hash>, right: &AggStateTransitionInputV2<Hash>) -> AggStateTransitionInputV2<Hash> {
            aggregate(left.get_state_transition(), right.get_state_transition(), false, false)
        }
    }

    fn aggregate(left: AggStateTransition<Hash>, right: AggStateTransition<Hash>, left_leaf: bool, right_leaf: bool) -> AggStateTransitionInputV2<Hash> {
        AggStateTransitionInputV2 {
            left_input: crate::agg::AggStateTransitionWithStats {
                state_transition_start: left.state_transition_start,
                state_transition_end: left.state_transition_end,
                total_proofs_generated: 1,
            },
            right_input: crate::agg::AggStateTransitionWithStats {
                state_transition_start: right.state_transition_start,
                state_transition_end: right.state_transition_end,
                total_proofs_generated: 1,
            },
            left_proof_is_leaf: left_leaf,
            right_proof_is_leaf: right_leaf,
        }
    }

    fn leaf(index: u64) -> Leaf {
        Leaf {
            left_input: AggStateTransition::new(Hash::from_values(index, 0, 0, 0), Hash::from_values(index + 1, 0, 0, 0)),
            right_input: AggStateTransition::new(Hash::from_values(index + 1, 0, 0, 0), Hash::from_values(index + 2, 0, 0, 0)),
            left_proof_is_leaf: true,
            right_proof_is_leaf: true,
        }
    }

    #[test]
    fn computes_expected_levels() {
        assert_eq!(compute_max_level(0), 0);
        assert_eq!(compute_max_level(1), 0);
        assert_eq!(compute_max_level(2), 1);
        assert_eq!(compute_max_level(3), 2);
        assert_eq!(compute_max_level(5), 3);
    }

    #[test]
    fn plans_dummy_single_and_mixed_subtrees() {
        let root = Hash::from_values(10, 0, 0, 0);
        let allowed = Hash::from_values(11, 0, 0, 0);
        for count in 0..=5 {
            let leaves = (0..count).map(|i| leaf(i as u64)).collect::<Vec<_>>();
            let (layers, witnesses) = plan_jobs_for_tree_agg::<QProvingJobDataID, PF, Hash, PoseidonHasher, Leaf, Helper>(7, root, allowed, &leaves).unwrap();
            let expected_jobs = if count == 0 { 1 } else { count * 2 - 1 };
            assert_eq!(layers.iter().map(Vec::len).sum::<usize>(), expected_jobs);
            assert_eq!(witnesses.len(), expected_jobs);
            assert_eq!(layers.len(), compute_max_level(count) as usize + 1);
            assert_eq!(layers.last().unwrap().len(), 1);
        }
    }

    #[test]
    fn offset_planner_rebases_reward_tree_coordinates() {
        let leaves = vec![leaf(0), leaf(1), leaf(2)];
        let (layers, witnesses) = plan_jobs_for_tree_agg_offset_root::<QProvingJobDataID, PF, Hash, PoseidonHasher, Leaf, Helper>(
            9,
            Hash::default(),
            Hash::from_values(12, 0, 0, 0),
            &leaves,
            6,
            4,
        ).unwrap();
        assert_eq!(witnesses.len(), 5);
        assert_eq!(layers.last().unwrap()[0].metadata.reward_tree_node_index, 6);
        assert_eq!(layers.last().unwrap()[0].metadata.reward_tree_node_level, 4);
        assert_eq!(layers[0][0].metadata.reward_tree_node_index, 24);
        assert_eq!(layers[0][0].metadata.reward_tree_node_level, 6);
        for layer in &layers {
            for job in layer {
                assert!(job.metadata.reward_tree_node_level >= 4);
            }
        }

        let (dummy_layers, dummy_witnesses) = plan_jobs_for_tree_agg_offset_root::<QProvingJobDataID, PF, Hash, PoseidonHasher, Leaf, Helper>(
            9, Hash::default(), Hash::default(), &[], 7, 5,
        ).unwrap();
        assert_eq!(dummy_layers[0][0].metadata.reward_tree_node_index, 7);
        assert_eq!(dummy_layers[0][0].metadata.reward_tree_node_level, 5);
        assert_eq!(dummy_witnesses.len(), 1);
    }

    #[test]
    fn planned_layers_carry_leaf_and_aggregation_metadata() {
        let leaves = vec![leaf(0), leaf(1), leaf(2), leaf(3), leaf(4)];
        let (layers, witnesses) = plan_jobs_for_tree_agg::<QProvingJobDataID, PF, Hash, PoseidonHasher, Leaf, Helper>(
            11,
            Hash::default(),
            Hash::from_values(12, 0, 0, 0),
            &leaves,
        )
        .unwrap();

        // The bottom layer holds leaf jobs: no children and no dependencies.
        assert!(!layers[0].is_empty());
        for job in &layers[0] {
            assert_eq!(job.metadata.reward_tree_node_children, 0);
            assert!(job.metadata.dependencies.is_empty());
            assert_eq!(job.metadata.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN);
        }

        // The top layer holds a single root aggregation job depending on both children.
        let root = layers.last().unwrap();
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].metadata.reward_tree_node_children, 2);
        assert_eq!(root[0].metadata.dependencies.len(), 2);
        assert_eq!(root[0].metadata.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD);
        assert_eq!(root[0].metadata.reward_tree_node_index, 0);
        assert_eq!(root[0].metadata.reward_tree_node_level, 0);

        // Intermediate layers mix leaf jobs (no children) with aggregation
        // jobs (two dependencies each), depending on how the leaf count splits.
        for layer in &layers[1..layers.len() - 1] {
            for job in layer {
                if job.metadata.reward_tree_node_children == 0 {
                    assert!(job.metadata.dependencies.is_empty());
                    assert_eq!(job.metadata.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN);
                } else {
                    assert_eq!(job.metadata.reward_tree_node_children, 2);
                    assert_eq!(job.metadata.dependencies.len(), 2);
                    assert_eq!(job.metadata.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD);
                }
            }
        }

        // Every planned job contributes exactly one witness.
        assert_eq!(witnesses.len(), layers.iter().map(Vec::len).sum::<usize>());
    }
}
