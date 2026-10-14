use hashbrown::HashMap;

use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    gates::{gate::GateRef, noop::NoopGate},
    hash::{hash_types::{HashOut, HashOutTarget}, poseidon::PoseidonHash},
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{Hasher, PoseidonGoldilocksConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::{cyclic_recursion::check_cyclic_proof_verifier_data, dummy_circuit::cyclic_base_proof},
};
use psy_client_data::qdata::checkpoint::PsyCheckpointLeaf;
use psy_common_circuit::{
    builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore},
    u32::{arithmetic_u32::{CircuitBuilderU32, U32Target}, gates::arithmetic_u32::U32ArithmeticGate},
    traits::CreatableTarget,
};
use psy_config::network_constants::CHECKPOINT_TREE_HEIGHT;
use psy_network_circuit::gadgets::qdata::checkpoint::PsyCheckpointLeafGadget;
use psy_plonky2_basic_helpers::builder::{
    core::CircuitBuilderHelpersCore,
    pad_circuit::CircuitBuilderQEDCommonGates,
    select::CircuitBuilderSelectHelpers,
};

use crate::gadgets::tag_tree::hash_tag_tree_node_circuit;

use super::historical_merkle_proof::{historical_merkle_proof, HistoricalMerkleProofTarget};

const MAX_REWARD_HEIGHT: usize = 21;
struct RewardJobCoordinates {
    user_id: Target,
    height: Target,
    path_index: Target,
    nullifier_index: Target,
}

#[derive(Clone, Debug)]
pub struct UserRewardTagWitness {
    pub tag_preimage: QHashOut<F>,
    pub leaf_left: QHashOut<F>,
    pub leaf_right: QHashOut<F>,
    pub leaf_tag: QHashOut<F>,
    pub siblings: [QHashOut<F>; MAX_REWARD_HEIGHT],
    pub parent_tags: [QHashOut<F>; MAX_REWARD_HEIGHT],
}

pub struct UserRewardTagTarget {
    pub tag_preimage: HashOutTarget,
    pub leaf_left: HashOutTarget,
    pub leaf_right: HashOutTarget,
    pub leaf_tag: HashOutTarget,
    pub siblings: [HashOutTarget; MAX_REWARD_HEIGHT],
    pub parent_tags: [HashOutTarget; MAX_REWARD_HEIGHT],
    pub root: HashOutTarget,
}

impl UserRewardTagTarget {
    pub(super) fn new(builder: &mut CircuitBuilder<F, 2>, reward: &RewardJobCoordinates) -> Self {
        let zero = builder.zero();
        let one = builder.one();
        builder.range_check(reward.height, 8);
        let heights: Vec<_> = (2..=MAX_REWARD_HEIGHT).map(|height| {
            let height = builder.constant(F::from_canonical_usize(height));
            builder.is_equal(reward.height, height)
        }).collect();
        let valid_height = builder.add_many(heights.iter().map(|bit| bit.target));
        builder.connect(valid_height, one);
        let path_bits = builder.split_le(reward.path_index, 32);
        let mut offset = zero;
        for (index, height) in heights.iter().enumerate() {
            offset = builder.mul_const_add(F::from_canonical_u32((1u32 << index) - 1), height.target, offset);
        }
        let nullifier = builder.add(offset, reward.path_index);
        builder.connect(reward.nullifier_index, nullifier);
        for (bit_index, bit) in path_bits.iter().enumerate() {
            let allowed = builder.add_many(heights.iter().enumerate()
                .filter(|(index, _)| bit_index < *index)
                .map(|(_, height)| height.target));
            let forbidden = builder.sub(one, allowed);
            let high_bit = builder.mul(forbidden, bit.target);
            builder.assert_zero(high_bit);
        }
        let tag_preimage = builder.add_virtual_hash();
        let leaf_left = builder.add_virtual_hash();
        let leaf_right = builder.add_virtual_hash();
        let leaf_tag = builder.add_virtual_hash();
        builder.connect(tag_preimage.elements[0], reward.user_id);
        builder.range_check(reward.user_id, 32);
        // Worker preimages are [user_id, 0, a, b], so reject only the all-zero preimage.
        let preimage_is_zero = builder.is_zero_hash(tag_preimage);
        builder.assert_zero(preimage_is_zero.target);
        builder.assert_non_zero_hash(leaf_tag);
        let owner_tag = builder.hash_two_to_one::<PoseidonHash>(tag_preimage, tag_preimage);
        builder.connect_hashes(owner_tag, leaf_tag);
        let siblings = std::array::from_fn(|_| builder.add_virtual_hash());
        let parent_tags = std::array::from_fn(|_| builder.add_virtual_hash());
        let mut root = hash_tag_tree_node_circuit::<PoseidonHash, F, 2>(builder, leaf_left, leaf_right, leaf_tag);
        for level in 0..MAX_REWARD_HEIGHT {
            let level_target = builder.constant(F::from_canonical_usize(level));
            let active = builder.is_less_than(8, level_target, reward.height);
            let inactive = builder.not(active);
            for target in siblings[level].elements.into_iter().chain(parent_tags[level].elements) {
                let unused = builder.mul(inactive.target, target);
                builder.assert_zero(unused);
            }
            let left = builder.select_hash(path_bits[level], siblings[level], root);
            let right = builder.select_hash(path_bits[level], root, siblings[level]);
            let parent = hash_tag_tree_node_circuit::<PoseidonHash, F, 2>(builder, left, right, parent_tags[level]);
            root = builder.select_hash(active, parent, root);
        }
        Self { tag_preimage, leaf_left, leaf_right, leaf_tag, siblings, parent_tags, root }
    }

    pub(super) fn set_witness(&self, witness: &mut PartialWitness<F>, input: &UserRewardTagWitness) -> anyhow::Result<()> {
        for (target, value) in [self.tag_preimage, self.leaf_left, self.leaf_right, self.leaf_tag]
            .into_iter().zip([input.tag_preimage, input.leaf_left, input.leaf_right, input.leaf_tag]) {
            witness.set_hash_target(target, value.0)?;
        }
        for (target, value) in self.siblings.iter().chain(&self.parent_tags)
            .zip(input.siblings.iter().chain(&input.parent_tags)) {
            witness.set_hash_target(*target, value.0)?;
        }
        Ok(())
    }
}
use crate::{
    bridge::gadgets::reward_nullifier::{
        RewardNullifierTargets,
        REWARD_NULLIFIER_HEIGHT, REWARD_NULLIFIER_EMPTY_ROOT,
    },
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

pub const USER_REWARD_AGGREGATE_DEGREE_BITS: usize = 16;
pub const USER_REWARD_LEAF_PUBLIC_INPUT_COUNT: usize = 15;
pub const USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT: usize = 15;
pub const USER_REWARD_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT: usize = 4 + 4 * 16;
pub const USER_REWARD_ROOT_PUBLIC_INPUT_COUNT: usize = 23;

const USER_REWARD_USER: usize = 0;
const USER_REWARD_SOURCE: usize = 1;
const USER_REWARD_SOURCE_LEAF_HASH: usize = 2;
const USER_REWARD_OLD: usize = 6;
const USER_REWARD_NEW: usize = 10;
const USER_REWARD_COUNT: usize = 14;
#[derive(Clone, Debug)]
pub struct UserRewardJobWitness {
    pub source_checkpoint_id: u32,
    pub height: u8,
    pub path_index: u32,
    pub tag: UserRewardTagWitness,
}

#[derive(Clone, Debug)]
pub struct UserRewardLeafWitness {
    pub user_id: u32,
    pub old_nullifier_root: HashOut<F>,
    pub job: UserRewardJobWitness,
    pub checkpoint_leaf: PsyCheckpointLeaf<F>,
    pub nullifier_siblings: [HashOut<F>; REWARD_NULLIFIER_HEIGHT],
}

#[derive(Clone, Debug)]
pub enum UserRewardAggregateWitness {
    Leaf { leaf: UserRewardLeafProof },
    Pair { left: UserRewardAggregateProof, right: UserRewardAggregateProof },
}

#[derive(Clone, Debug)]
pub struct UserRewardRootWitness {
    pub recipient: [u32; 8],
    pub checkpoint_tree_root: HashOut<F>,
    pub checkpoint_leaf: PsyCheckpointLeaf<F>,
    pub checkpoint_siblings: [HashOut<F>; CHECKPOINT_TREE_HEIGHT as usize],
    pub aggregate_proof: UserRewardAggregateProof,
}

pub type UserRewardLeafProof = ProofWithPublicInputs<F, C, D>;
pub type UserRewardAggregateProof = ProofWithPublicInputs<F, C, D>;
pub type UserRewardRootProof = ProofWithPublicInputs<F, C, D>;

#[derive(Clone, Copy)]
struct U64Limbs { low: U32Target, high: U32Target }

struct JobTargets {
    source: Target, height: Target, path_index: Target, coordinate: Target,
    tag: UserRewardTagTarget,
}

pub struct UserRewardLeafTargets {
    pub user_id: Target,
    pub source_checkpoint_id: Target,
    pub source_checkpoint_leaf_hash: HashOutTarget,
    pub old_nullifier_root: HashOutTarget,
    pub new_nullifier_root: HashOutTarget,
    pub job_count: Target,
    job: JobTargets,
    checkpoint_leaf: PsyCheckpointLeafGadget,
    nullifier: RewardNullifierTargets,
}

pub struct UserRewardAggregateTargets {
    pub is_leaf: BoolTarget,
    pub is_pair: BoolTarget,
    pub user_id: Target,
    pub source_checkpoint_id: Target,
    pub source_checkpoint_leaf_hash: HashOutTarget,
    pub old_nullifier_root: HashOutTarget,
    pub new_nullifier_root: HashOutTarget,
    pub job_count: Target,
    leaf_proof: ProofWithPublicInputsTarget<D>,
    inactive_leaf_proof: ProofWithPublicInputsTarget<D>,
    child_proofs: [ProofWithPublicInputsTarget<D>; 2],
    pinned_aggregate: VerifierCircuitTarget,
}

pub struct UserRewardRootTargets {
    pub user_id: Target,
    pub recipient: [Target; 8],
    pub source_checkpoint_id: Target,
    pub job_count: Target,
    pub amount: [Target; 8],
    remainder: U64Limbs,
    pub checkpoint_tree_root: HashOutTarget,
    source: HistoricalMerkleProofTarget,
    aggregate_proof: ProofWithPublicInputsTarget<D>,
}

pub struct UserRewardLeafCircuit {
    pub targets: UserRewardLeafTargets,
    pub circuit_data: CircuitData<F, C, D>,
    pub fingerprint: QHashOut<F>,
}

pub struct UserRewardAggregateCircuit {
    pub targets: UserRewardAggregateTargets,
    pub circuit_data: CircuitData<F, C, D>,
    pub fingerprint: QHashOut<F>,
    dummy_leaf_proof: ProofWithPublicInputs<F, C, D>,
}

pub struct UserRewardRootCircuit {
    pub targets: UserRewardRootTargets,
    pub circuit_data: CircuitData<F, C, D>,
    pub fingerprint: QHashOut<F>,
}

fn pi_hash(inputs: &[Target], start: usize) -> HashOutTarget {
    HashOutTarget { elements: [inputs[start], inputs[start + 1], inputs[start + 2], inputs[start + 3]] }
}

fn hash_value(inputs: &[F], start: usize) -> HashOut<F> {
    HashOut { elements: std::array::from_fn(|index| inputs[start + index]) }
}

fn checked_add_u32(builder: &mut CircuitBuilder<F, D>, left: Target, right: Target) -> Target {
    let (sum, carry) = builder.add_u32(U32Target(left), U32Target(right));
    builder.assert_zero_u32(carry);
    sum.0
}

fn add_u128(builder: &mut CircuitBuilder<F, D>, left: [U32Target; 4], right: [U32Target; 4]) -> [U32Target; 4] {
    let mut carry = builder.zero_u32();
    let sum = std::array::from_fn(|index| {
        let (limb, next_carry) = builder.add_many_u32(&[left[index], right[index], carry]);
        carry = next_carry;
        limb
    });
    builder.assert_zero_u32(carry);
    sum
}

fn canonical_limbs(builder: &mut CircuitBuilder<F, D>, limbs: U64Limbs) {
    builder.range_check(limbs.low.0, 32);
    builder.range_check(limbs.high.0, 32);
    let maximum = builder.constant(F::from_canonical_u32(u32::MAX));
    let high_maximum = builder.is_equal(limbs.high.0, maximum);
    let forbidden_low = builder.mul(high_maximum.target, limbs.low.0);
    builder.assert_zero(forbidden_low);
}

fn canonical_u64(builder: &mut CircuitBuilder<F, D>, value: Target) -> U64Limbs {
    let (low, high) = builder.split_low_high(value, 32, 64);
    let limbs = U64Limbs { low: U32Target(low), high: U32Target(high) };
    canonical_limbs(builder, limbs);
    limbs
}

fn product_u64(builder: &mut CircuitBuilder<F, D>, left: U64Limbs, right: U64Limbs) -> [U32Target; 4] {
    let (p00, c00) = builder.mul_u32(left.low, right.low);
    let (p01, c01) = builder.mul_u32(left.low, right.high);
    let (p10, c10) = builder.mul_u32(left.high, right.low);
    let (p11, c11) = builder.mul_u32(left.high, right.high);
    let (limb1, carry1) = builder.add_many_u32(&[c00, p01, p10]);
    let (limb2, carry2) = builder.add_many_u32(&[c01, c10, p11, carry1]);
    let (limb3, overflow) = builder.add_u32(c11, carry2);
    builder.assert_zero_u32(overflow);
    [p00, limb1, limb2, limb3]
}

fn assert_less_equal_u128(builder: &mut CircuitBuilder<F, D>, left: &[U32Target; 4], right: &[U32Target; 4]) {
    let mut decided = builder._false();
    let mut less = builder._false();
    for index in (0..4).rev() {
        let current_less = builder.is_less_than(32, left[index].0, right[index].0);
        let equal = builder.is_equal(left[index].0, right[index].0);
        let undecided = builder.not(decided);
        let newly_less = builder.and(undecided, current_less);
        less = builder.or(less, newly_less);
        let unequal = builder.not(equal);
        decided = builder.or(decided, unequal);
    }
    let equal = builder.not(decided);
    let accepted = builder.or(less, equal);
    builder.assert_one(accepted.target);
}

fn authenticated_job(builder: &mut CircuitBuilder<F, D>, user_id: Target) -> JobTargets {
    let source = builder.add_virtual_target();
    builder.range_check(source, 32);
    let reward = RewardJobCoordinates {
        user_id, height: builder.add_virtual_target(), path_index: builder.add_virtual_target(),
        nullifier_index: builder.add_virtual_target(),
    };
    let tag = UserRewardTagTarget::new(builder, &reward);
    JobTargets { source, height: reward.height, path_index: reward.path_index, coordinate: reward.nullifier_index, tag }
}

fn build_leaf() -> UserRewardLeafCircuit {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let user_id = builder.add_virtual_target();
    let job = authenticated_job(&mut builder, user_id);
    let source_checkpoint_id = job.source;
    let checkpoint_leaf = PsyCheckpointLeafGadget::create_virtual(&mut builder);
    let source_checkpoint_leaf_hash = checkpoint_leaf.to_hash::<PoseidonHash, F, D>(&mut builder);
    builder.connect_hashes(job.tag.root, checkpoint_leaf.stats.pm_rewards_commitment.gutas_root);
    let nullifier = RewardNullifierTargets::add(&mut builder);
    builder.connect(nullifier.index, job.coordinate);
    let targets = UserRewardLeafTargets {
        user_id, source_checkpoint_id, source_checkpoint_leaf_hash,
        old_nullifier_root: nullifier.old_nullifier_root, new_nullifier_root: nullifier.new_nullifier_root,
        job_count: builder.one(), job, checkpoint_leaf, nullifier,
    };
    let mut fields = vec![user_id, source_checkpoint_id];
    fields.extend(source_checkpoint_leaf_hash.elements);
    fields.extend(targets.old_nullifier_root.elements);
    fields.extend(targets.new_nullifier_root.elements);
    fields.push(targets.job_count);
    builder.register_public_inputs(&fields);
    let circuit_data = builder.build::<C>();
    assert_eq!(circuit_data.common.num_public_inputs, USER_REWARD_LEAF_PUBLIC_INPUT_COUNT);
    let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
    UserRewardLeafCircuit { targets, circuit_data, fingerprint }
}

fn aggregate_gates(builder: &mut CircuitBuilder<F, D>, leaf: &UserRewardLeafCircuit) {
    builder.add_qed_type_d_common_gates();
    for gate in &leaf.circuit_data.common.gates { builder.add_gate_to_gate_set(gate.clone()); }
    builder.add_gate_to_gate_set(GateRef::new(U32ArithmeticGate::<F, D>::new_from_config(&builder.config)));
}

fn aggregate_common_data(leaf: &UserRewardLeafCircuit) -> CommonCircuitData<F, D> {
    let config = CircuitConfig::standard_recursion_config();
    let mut stage = CircuitBuilder::<F, D>::new(config.clone());
    aggregate_gates(&mut stage, leaf);
    let proof = stage.add_virtual_proof_with_pis(&leaf.circuit_data.common);
    let verifier = stage.add_virtual_verifier_data(leaf.circuit_data.common.config.fri_config.cap_height);
    stage.verify_proof::<C>(&proof, &verifier, &leaf.circuit_data.common);
    let data = stage.build::<C>();
    let mut stage = CircuitBuilder::<F, D>::new(config.clone());
    aggregate_gates(&mut stage, leaf);
    let proof = stage.add_virtual_proof_with_pis(&data.common);
    let verifier = stage.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    stage.verify_proof::<C>(&proof, &verifier, &data.common);
    let data = stage.build::<C>();
    let mut stage = CircuitBuilder::<F, D>::new(config);
    aggregate_gates(&mut stage, leaf);
    let proof = stage.add_virtual_proof_with_pis(&data.common);
    let verifier = stage.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    stage.verify_proof::<C>(&proof, &verifier, &data.common);
    while stage.num_gates() < 1 << USER_REWARD_AGGREGATE_DEGREE_BITS { stage.add_gate(NoopGate, vec![]); }
    let mut common = stage.build::<C>().common;
    assert_eq!(common.config.fri_config.cap_height, 4);
    common.num_public_inputs = USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT + USER_REWARD_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT;
    common
}

fn connect_if(builder: &mut CircuitBuilder<F, D>, condition: BoolTarget, left: Target, right: Target) {
    let selected = builder.select(condition, left, right);
    builder.connect(selected, right);
}

fn build_aggregate(leaf: &UserRewardLeafCircuit) -> UserRewardAggregateCircuit {
    let child_common = aggregate_common_data(leaf);
    let leaf_dummy = plonky2::recursion::dummy_circuit::dummy_circuit::<F, C, D>(&leaf.circuit_data.common);
    let dummy_leaf_proof = plonky2::recursion::dummy_circuit::dummy_proof::<F, C, D>(&leaf_dummy, HashMap::new()).expect("reward leaf dummy");
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    aggregate_gates(&mut builder, leaf);
    let is_leaf = builder.add_virtual_bool_target_safe();
    let is_pair = builder.not(is_leaf);
    let leaf_proof = builder.add_virtual_proof_with_pis(&leaf.circuit_data.common);
    let pinned_leaf = builder.constant_verifier_data(&leaf.circuit_data.verifier_only);
    let (inactive_leaf_proof, inactive_leaf_verifier) = builder
        .dummy_proof_and_constant_vk_no_generator::<C>(&leaf.circuit_data.common)
        .expect("reward aggregate inactive leaf proof");
    builder.conditionally_verify_proof::<C>(is_leaf, &leaf_proof, &pinned_leaf,
        &inactive_leaf_proof, &inactive_leaf_verifier, &leaf.circuit_data.common);
    let child_proofs = std::array::from_fn(|_| builder.add_virtual_proof_with_pis(&child_common));
    let fields: [Target; USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT] = std::array::from_fn(|_| builder.add_virtual_target());
    builder.register_public_inputs(&fields);
    let pinned_aggregate = builder.add_verifier_data_public_inputs();
    for child in &child_proofs {
        builder.conditionally_verify_cyclic_proof_or_dummy::<C>(is_pair, child, &child_common).expect("reward aggregate cyclic verifier");
    }
    let left = &child_proofs[0].public_inputs;
    let right = &child_proofs[1].public_inputs;
    for index in 0..USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT {
        connect_if(&mut builder, is_leaf, leaf_proof.public_inputs[index], fields[index]);
    }
    for index in USER_REWARD_USER..USER_REWARD_OLD {
        connect_if(&mut builder, is_pair, left[index], fields[index]);
        connect_if(&mut builder, is_pair, right[index], fields[index]);
    }
    for index in 0..4 {
        connect_if(&mut builder, is_pair, left[USER_REWARD_OLD + index], fields[USER_REWARD_OLD + index]);
        connect_if(&mut builder, is_pair, right[USER_REWARD_NEW + index], fields[USER_REWARD_NEW + index]);
        connect_if(&mut builder, is_pair, left[USER_REWARD_NEW + index], right[USER_REWARD_OLD + index]);
    }
    let pair_count = checked_add_u32(&mut builder, left[USER_REWARD_COUNT], right[USER_REWARD_COUNT]);
    connect_if(&mut builder, is_pair, pair_count, fields[USER_REWARD_COUNT]);
    let targets = UserRewardAggregateTargets {
        is_leaf, is_pair, user_id: fields[USER_REWARD_USER], source_checkpoint_id: fields[USER_REWARD_SOURCE],
        source_checkpoint_leaf_hash: pi_hash(&fields, USER_REWARD_SOURCE_LEAF_HASH),
        old_nullifier_root: pi_hash(&fields, USER_REWARD_OLD), new_nullifier_root: pi_hash(&fields, USER_REWARD_NEW),
        job_count: fields[USER_REWARD_COUNT],
        leaf_proof, inactive_leaf_proof, child_proofs, pinned_aggregate,
    };
    while builder.num_gates() < 1 << USER_REWARD_AGGREGATE_DEGREE_BITS { builder.add_gate(NoopGate, vec![]); }
    let (circuit_data, matches) = builder.try_build_with_options::<C>(true);
    assert!(matches, "reward aggregate common data mismatch");
    assert_eq!(circuit_data.common.num_public_inputs, USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT + USER_REWARD_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT);
    let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
    UserRewardAggregateCircuit { targets, fingerprint, circuit_data, dummy_leaf_proof }
}

impl UserRewardLeafCircuit {
    pub fn new() -> Self { build_leaf() }

    fn set_witness(&self, input: &UserRewardLeafWitness) -> anyhow::Result<PartialWitness<F>> {
        let mut witness = PartialWitness::new();
        witness.set_target(self.targets.user_id, F::from_canonical_u32(input.user_id))?;
        witness.set_hash_target(self.targets.old_nullifier_root, input.old_nullifier_root)?;
        self.targets.checkpoint_leaf.set_witness(&mut witness, &input.checkpoint_leaf)?;
        witness.set_target(self.targets.job.source, F::from_canonical_u32(input.job.source_checkpoint_id))?;
        witness.set_target(self.targets.job.height, F::from_canonical_u8(input.job.height))?;
        witness.set_target(self.targets.job.path_index, F::from_canonical_u32(input.job.path_index))?;
        self.targets.job.tag.set_witness(&mut witness, &input.job.tag)?;
        for (&target, sibling) in self.targets.nullifier.nullifier_siblings.iter().zip(input.nullifier_siblings) {
            witness.set_hash_target(target, sibling)?;
        }
        Ok(witness)
    }

    pub fn prove(&self, input: &UserRewardLeafWitness) -> anyhow::Result<UserRewardLeafProof> {
        self.circuit_data.prove(self.set_witness(input)?)
    }
}

fn aggregate_public_inputs(proof: &UserRewardAggregateProof) -> anyhow::Result<&[F]> {
    anyhow::ensure!(proof.public_inputs.len() == USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT + USER_REWARD_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT, "reward aggregate statement width mismatch");
    Ok(&proof.public_inputs)
}

impl UserRewardAggregateCircuit {
    pub fn new(leaf: &UserRewardLeafCircuit) -> Self { build_aggregate(leaf) }

    fn set_witness(&self, input: &UserRewardAggregateWitness) -> anyhow::Result<PartialWitness<F>> {
        let mut witness = PartialWitness::new();
        let identity;
        let (is_leaf, leaf, left, right, statement, new_root, job_count) = match input {
            UserRewardAggregateWitness::Leaf { leaf } => {
                anyhow::ensure!(leaf.public_inputs.len() == USER_REWARD_LEAF_PUBLIC_INPUT_COUNT, "reward leaf statement width mismatch");
                identity = cyclic_base_proof(&self.circuit_data.common, &self.circuit_data.verifier_only, HashMap::new());
                (true, leaf, &identity, &identity, &leaf.public_inputs,
                    hash_value(&leaf.public_inputs, USER_REWARD_NEW), leaf.public_inputs[USER_REWARD_COUNT])
            }
            UserRewardAggregateWitness::Pair { left, right } => {
                let (a, b) = (aggregate_public_inputs(left)?, aggregate_public_inputs(right)?);
                anyhow::ensure!(a[..USER_REWARD_OLD] == b[..USER_REWARD_OLD], "reward aggregate common fields differ");
                anyhow::ensure!(a[USER_REWARD_NEW..USER_REWARD_COUNT] == b[USER_REWARD_OLD..USER_REWARD_NEW], "reward aggregate continuity is broken");
                let count = u32::try_from(a[USER_REWARD_COUNT].to_canonical_u64())?
                    .checked_add(u32::try_from(b[USER_REWARD_COUNT].to_canonical_u64())?)
                    .ok_or_else(|| anyhow::anyhow!("reward aggregate count overflow"))?;
                check_cyclic_proof_verifier_data(left, &self.circuit_data.verifier_only, &self.circuit_data.common)?;
                check_cyclic_proof_verifier_data(right, &self.circuit_data.verifier_only, &self.circuit_data.common)?;
                (false, &self.dummy_leaf_proof, left, right, &left.public_inputs,
                    hash_value(b, USER_REWARD_NEW), F::from_canonical_u32(count))
            }
        };
        witness.set_bool_target(self.targets.is_leaf, is_leaf)?;
        witness.set_verifier_data_target(&self.targets.pinned_aggregate, &self.circuit_data.verifier_only)?;
        witness.set_proof_with_pis_target(&self.targets.leaf_proof, leaf)?;
        witness.set_proof_with_pis_target(&self.targets.inactive_leaf_proof, &self.dummy_leaf_proof)?;
        witness.set_proof_with_pis_target(&self.targets.child_proofs[0], left)?;
        witness.set_proof_with_pis_target(&self.targets.child_proofs[1], right)?;
        witness.set_target(self.targets.user_id, statement[USER_REWARD_USER])?;
        witness.set_target(self.targets.source_checkpoint_id, statement[USER_REWARD_SOURCE])?;
        witness.set_hash_target(self.targets.source_checkpoint_leaf_hash, hash_value(statement, USER_REWARD_SOURCE_LEAF_HASH))?;
        witness.set_hash_target(self.targets.old_nullifier_root, hash_value(statement, USER_REWARD_OLD))?;
        witness.set_hash_target(self.targets.new_nullifier_root, new_root)?;
        witness.set_target(self.targets.job_count, job_count)?;
        Ok(witness)
    }

    pub fn prove(&self, input: &UserRewardAggregateWitness) -> anyhow::Result<UserRewardAggregateProof> {
        let proof = self.circuit_data.prove(self.set_witness(input)?)?;
        check_cyclic_proof_verifier_data(&proof, &self.circuit_data.verifier_only, &self.circuit_data.common)?;
        Ok(proof)
    }
}

fn bind_suffix(builder: &mut CircuitBuilder<F, D>, inputs: &[Target], verifier: &VerifierCircuitTarget) {
    let start = USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT;
    assert_eq!(inputs.len() - start, USER_REWARD_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT);
    assert_eq!(verifier.constants_sigmas_cap.0.len(), 16);
    for index in 0..4 { builder.connect(inputs[start + index], verifier.circuit_digest.elements[index]); }
    for (index, cap) in verifier.constants_sigmas_cap.0.iter().enumerate() {
        for limb in 0..4 { builder.connect(inputs[start + 4 + 4 * index + limb], cap.elements[limb]); }
    }
}

fn exact_payout(builder: &mut CircuitBuilder<F, D>, job_count: Target, fees: U64Limbs, completed: U64Limbs) -> (U64Limbs, U64Limbs) {
    builder.range_check(job_count, 32);
    builder.assert_non_zero(job_count);
    canonical_limbs(builder, fees);
    canonical_limbs(builder, completed);
    let completed_value = builder.mul_const_add(F::from_canonical_u64(1 << 32), completed.high.0, completed.low.0);
    builder.assert_non_zero(completed_value);
    let zero = builder.zero_u32();
    assert_less_equal_u128(builder, &[U32Target(job_count), zero, zero, zero], &[completed.low, completed.high, zero, zero]);
    let amount = U64Limbs { low: builder.add_virtual_u32_target(), high: builder.add_virtual_u32_target() };
    let remainder = U64Limbs { low: builder.add_virtual_u32_target(), high: builder.add_virtual_u32_target() };
    canonical_limbs(builder, amount);
    canonical_limbs(builder, remainder);
    let high_less = builder.is_less_than(32, remainder.high.0, completed.high.0);
    let high_equal = builder.is_equal(remainder.high.0, completed.high.0);
    let low_less = builder.is_less_than(32, remainder.low.0, completed.low.0);
    let equal_high_less_low = builder.and(high_equal, low_less);
    let remainder_in_range = builder.or(high_less, equal_high_less_low);
    builder.assert_one(remainder_in_range.target);
    let numerator = product_u64(builder, U64Limbs { low: U32Target(job_count), high: zero }, fees);
    let paid = product_u64(builder, amount, completed);
    let reconstructed = add_u128(builder, paid, [remainder.low, remainder.high, zero, zero]);
    for index in 0..4 { builder.connect(numerator[index].0, reconstructed[index].0); }
    (amount, remainder)
}

fn build_root(aggregate: &UserRewardAggregateCircuit) -> UserRewardRootCircuit {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let zero = builder.zero();
    let aggregate_proof = builder.add_virtual_proof_with_pis(&aggregate.circuit_data.common);
    let aggregate_verifier = builder.constant_verifier_data(&aggregate.circuit_data.verifier_only);
    builder.verify_proof::<C>(&aggregate_proof, &aggregate_verifier, &aggregate.circuit_data.common);
    bind_suffix(&mut builder, &aggregate_proof.public_inputs, &aggregate_verifier);
    let child = &aggregate_proof.public_inputs;
    let user_id = child[USER_REWARD_USER];
    let source_checkpoint_id = child[USER_REWARD_SOURCE];
    let checkpoint_tree_root = builder.add_virtual_hash();
    let empty_root = builder.constant_hash(*REWARD_NULLIFIER_EMPTY_ROOT);
    builder.connect_hashes(pi_hash(child, USER_REWARD_OLD), empty_root);
    let job_count = child[USER_REWARD_COUNT];
    let checkpoint_leaf = PsyCheckpointLeafGadget::create_virtual(&mut builder);
    let source = historical_merkle_proof(&mut builder, [source_checkpoint_id, zero], &checkpoint_leaf, [source_checkpoint_id, zero], checkpoint_tree_root);
    builder.connect_hashes(source.checkpoint_leaf_hash, pi_hash(child, USER_REWARD_SOURCE_LEAF_HASH));
    let fees = canonical_u64(&mut builder, checkpoint_leaf.stats.guta_fees_collected);
    let completed = canonical_u64(&mut builder, checkpoint_leaf.stats.pm_jobs_completed.gutas_completed);
    let (payout, remainder) = exact_payout(&mut builder, job_count, fees, completed);
    let amount = [payout.low.0, payout.high.0, zero, zero, zero, zero, zero, zero];
    builder.range_check(user_id, 32);
    let recipient: [Target; 8] = std::array::from_fn(|index| {
        let target = builder.add_virtual_target();
        if index < 5 { builder.range_check(target, 32); } else { builder.assert_zero(target); }
        target
    });
    let mut statement = vec![user_id];
    statement.extend(recipient);
    statement.push(source_checkpoint_id);
    statement.push(job_count);
    statement.extend(amount);
    statement.extend(checkpoint_tree_root.elements);
    assert_eq!(statement.len(), USER_REWARD_ROOT_PUBLIC_INPUT_COUNT);
    builder.register_public_inputs(&statement);
    let circuit_data = builder.build::<C>();
    assert_eq!(circuit_data.common.num_public_inputs, USER_REWARD_ROOT_PUBLIC_INPUT_COUNT);
    let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
    UserRewardRootCircuit {
        targets: UserRewardRootTargets {
            user_id, recipient, source_checkpoint_id, job_count, amount, remainder, checkpoint_tree_root,
            source, aggregate_proof,
        },
        circuit_data, fingerprint,
    }
}

impl UserRewardRootCircuit {
    pub fn new(aggregate: &UserRewardAggregateCircuit) -> Self { build_root(aggregate) }

    fn set_witness(&self, input: &UserRewardRootWitness) -> anyhow::Result<PartialWitness<F>> {
        anyhow::ensure!(input.recipient[5..].iter().all(|limb| *limb == 0), "recipient exceeds 160 bits");
        let child = aggregate_public_inputs(&input.aggregate_proof)?;
        let count = u32::try_from(child[USER_REWARD_COUNT].to_canonical_u64())?;
        let fees = input.checkpoint_leaf.stats.guta_fees_collected.to_canonical_u64();
        let completed = input.checkpoint_leaf.stats.pm_jobs_completed.gutas_completed.to_canonical_u64();
        anyhow::ensure!(count > 0 && completed > 0 && u64::from(count) <= completed, "reward job count exceeds completed jobs or is zero");
        let numerator = u128::from(count) * u128::from(fees);
        let amount = (numerator / u128::from(completed)) as u64;
        let remainder = (numerator % u128::from(completed)) as u64;
        let mut witness = PartialWitness::new();
        witness.set_target(self.targets.amount[0], F::from_canonical_u32(amount as u32))?;
        witness.set_target(self.targets.amount[1], F::from_canonical_u32((amount >> 32) as u32))?;
        witness.set_target(self.targets.remainder.low.0, F::from_canonical_u32(remainder as u32))?;
        witness.set_target(self.targets.remainder.high.0, F::from_canonical_u32((remainder >> 32) as u32))?;
        for (&target, limb) in self.targets.recipient.iter().zip(input.recipient) { witness.set_target(target, F::from_canonical_u32(limb))?; }
        witness.set_hash_target(self.targets.checkpoint_tree_root, input.checkpoint_tree_root)?;
        self.targets.source.checkpoint_leaf.set_witness(&mut witness, &input.checkpoint_leaf)?;
        for (&target, sibling) in self.targets.source.path.siblings.iter().zip(input.checkpoint_siblings) {
            witness.set_hash_target(target, sibling)?;
        }
        witness.set_proof_with_pis_target(&self.targets.aggregate_proof, &input.aggregate_proof)?;
        Ok(witness)
    }

    pub fn prove(&self, input: &UserRewardRootWitness) -> anyhow::Result<UserRewardRootProof> {
        self.circuit_data.prove(self.set_witness(input)?)
    }
}

impl QStandardCircuit<C, D> for UserRewardLeafCircuit {
    fn get_fingerprint(&self) -> QHashOut<F> { self.fingerprint }
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> { &self.circuit_data.verifier_only }
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<F, D> { &self.circuit_data.common }
}

impl QStandardCircuit<C, D> for UserRewardAggregateCircuit {
    fn get_fingerprint(&self) -> QHashOut<F> { self.fingerprint }
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> { &self.circuit_data.verifier_only }
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<F, D> { &self.circuit_data.common }
}

impl QStandardCircuit<C, D> for UserRewardRootCircuit {
    fn get_fingerprint(&self) -> QHashOut<F> { self.fingerprint }
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> { &self.circuit_data.verifier_only }
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<F, D> { &self.circuit_data.common }
}

#[cfg(test)]
pub(in crate::bridge::circuits) mod tests {
    use super::*;
    use crate::bridge::gadgets::reward_nullifier::{nullifier_job_index, REWARD_NULLIFIER_OCCUPIED_LEAF};
    use psy_client_data::qdata::checkpoint::PsyCheckpointGlobalStateRoots;
    use psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT;
    use psy_crypto::hash::traits::qhashable::QFieldHashable;

    fn tagged(left: HashOut<F>, right: HashOut<F>, tag: HashOut<F>) -> HashOut<F> {
        PoseidonHash::two_to_one(PoseidonHash::two_to_one(left, right), tag)
    }

    pub(in crate::bridge::circuits) struct Fixture {
        pub(in crate::bridge::circuits) user_id: u32,
        pub(in crate::bridge::circuits) anchor_checkpoint_id: u32,
        pub(in crate::bridge::circuits) anchor_leaf: PsyCheckpointLeaf<F>,
        checkpoint: PsyCheckpointLeaf<F>, pub(in crate::bridge::circuits) checkpoints: Leaves, pub(super) jobs: Vec<UserRewardJobWitness>,
        nullifiers: Leaves,
    }

    impl Fixture {
        fn new() -> Self { Self::for_user(7, 12) }

        pub(in crate::bridge::circuits) fn for_user(user_id: u32, anchor_checkpoint_id: u32) -> Self {
            let preimage = QHashOut::from_values(u64::from(user_id), 0, 4, 8);
            let tag = PoseidonHash::two_to_one(preimage.0, preimage.0);
            let mut levels = vec![(0..64).map(|index| tagged(QHashOut::from_values(index, 0, 0, 0).0, HashOut::ZERO, tag)).collect::<Vec<_>>()];
            for level in 0..6 {
                let parents = levels[level].chunks_exact(2).map(|pair| tagged(pair[0], pair[1], HashOut::ZERO)).collect();
                levels.push(parents);
            }
            let jobs = (0..16).map(|index| UserRewardJobWitness {
                source_checkpoint_id: 10, height: 6, path_index: index as u32,
                tag: UserRewardTagWitness {
                    tag_preimage: preimage, leaf_left: QHashOut::from_values(index as u64, 0, 0, 0),
                    leaf_right: QHashOut::ZERO, leaf_tag: QHashOut(tag),
                    siblings: std::array::from_fn(|level| if level < 6 { QHashOut(levels[level][(index >> level) ^ 1]) } else { QHashOut::ZERO }),
                    parent_tags: [QHashOut::ZERO; 21],
                },
            }).collect();
            let mut checkpoint = PsyCheckpointLeaf::default();
            checkpoint.stats.pm_rewards_commitment.gutas_root.0 = levels[6][0];
            checkpoint.stats.pm_jobs_completed.gutas_completed = F::from_canonical_u32(64);
            checkpoint.stats.guta_fees_collected = F::from_canonical_u32(640);
            let hash = checkpoint.qfhash::<PoseidonHash>().0;
            let mut checkpoints = Leaves::from([(10, hash), (11, hash), (1024, hash), (2048, hash)]);
            let anchor_leaf = anchor_leaf(user_id);
            checkpoints.insert(u64::from(anchor_checkpoint_id), anchor_leaf.qfhash::<PoseidonHash>().0);
            Self { user_id, anchor_checkpoint_id, anchor_leaf, checkpoint, checkpoints, jobs, nullifiers: Leaves::new() }
        }

        pub(in crate::bridge::circuits) fn node(&mut self, source: u32, index: usize) -> UserRewardLeafWitness {
            let mut job = self.jobs[index].clone();
            job.source_checkpoint_id = source;
            let coordinate = u64::from(nullifier_job_index(job.height, job.path_index).unwrap());
            let (nullifier_siblings, old_nullifier_root) = path::<20>(&self.nullifiers, coordinate, HashOut::ZERO);
            self.nullifiers.insert(coordinate, REWARD_NULLIFIER_OCCUPIED_LEAF);
            UserRewardLeafWitness {
                user_id: self.user_id, old_nullifier_root, job,
                checkpoint_leaf: self.checkpoint.clone(), nullifier_siblings,
            }
        }
    }

    pub(super) fn reward_fixture() -> Fixture { Fixture::for_user(7, 12) }

    pub(in crate::bridge::circuits) fn registration_membership(user_id: u32) -> (HashOut<F>, u64, [HashOut<F>; GLOBAL_USER_TREE_HEIGHT as usize], PsyCheckpointGlobalStateRoots<F>) {
        let private_key = QHashOut::from_values(17, 23, 31, 47);
        let client_key = psy_client_common::data::qhashout::QHashOut(private_key.0);
        let public_key_param = psy_ups_circuit::signature::software_defined::get_sdc_public_key_param(&client_key);
        let fingerprint = psy_common_circuit::circuits::zk_signature3::core::PsyBasicZKSignatureCircuit::<C, D>::new().fingerprint.0;
        let registration_leaf = PoseidonHash::two_to_one(fingerprint, public_key_param.0);
        let registration_index = psy_crypto::common::user_id::get_registration_id_from_user_id(u64::from(user_id));
        let (registration_siblings, registration_root) = path::<{ GLOBAL_USER_TREE_HEIGHT as usize }>(
            &Leaves::from([(registration_index, registration_leaf)]), registration_index, HashOut::ZERO,
        );
        let mut global_roots = psy_client_data::qdata::checkpoint::PsyCheckpointGlobalStateRoots::default();
        global_roots.user_registration_tree_root.0 = registration_root;
        (registration_leaf, registration_index, registration_siblings, global_roots)
    }

    fn anchor_leaf(user_id: u32) -> PsyCheckpointLeaf<F> {
        let (_, _, _, global_roots) = registration_membership(user_id);
        let mut anchor_leaf = PsyCheckpointLeaf::default();
        anchor_leaf.global_chain_root = global_roots.qfhash::<PoseidonHash>();
        anchor_leaf
    }

    pub(in crate::bridge::circuits) fn root_witness(fixture: &Fixture, recipient: u64, aggregate_proof: UserRewardAggregateProof) -> UserRewardRootWitness {
        let source = aggregate_proof.public_inputs[USER_REWARD_SOURCE].to_canonical_u64();
        let (checkpoint_siblings, checkpoint_tree_root) = path::<32>(&fixture.checkpoints, source, HashOut::ZERO);
        UserRewardRootWitness {
            recipient: [recipient as u32, 2, 3, 4, 5, 0, 0, 0],
            checkpoint_tree_root, checkpoint_leaf: fixture.checkpoint.clone(), checkpoint_siblings, aggregate_proof,
        }
    }

    pub(in crate::bridge::circuits) fn reward_root(root: &UserRewardRootCircuit, fixture: &Fixture, recipient: u64, aggregate_proof: UserRewardAggregateProof) -> UserRewardRootProof {
        root.prove(&root_witness(fixture, recipient, aggregate_proof)).unwrap()
    }

    fn lift(aggregate: &UserRewardAggregateCircuit, proof: UserRewardLeafProof) -> UserRewardAggregateProof {
        aggregate.prove(&UserRewardAggregateWitness::Leaf { leaf: proof }).unwrap()
    }

    fn pair(aggregate: &UserRewardAggregateCircuit, left: UserRewardAggregateProof, right: UserRewardAggregateProof) -> UserRewardAggregateProof {
        aggregate.prove(&UserRewardAggregateWitness::Pair { left, right }).unwrap()
    }

    #[test]
    fn singleton_odd_even_and_parenthesizations_pay_exactly_once() {
        let leaf = UserRewardLeafCircuit::new();
        let aggregate = UserRewardAggregateCircuit::new(&leaf);
        let root = UserRewardRootCircuit::new(&aggregate);
        let mut fixture = Fixture::new();
        fixture.checkpoint.stats.guta_fees_collected = F::from_canonical_u32(100);
        fixture.checkpoints.insert(10, fixture.checkpoint.qfhash::<PoseidonHash>().0);
        let proofs: Vec<_> = [12, 0, 3, 7].into_iter().map(|index| {
            let proof = leaf.prove(&fixture.node(10, index)).unwrap();
            leaf.circuit_data.verify(proof.clone()).unwrap();
            let statement = proof.public_inputs.clone();
            let lifted = lift(&aggregate, proof);
            assert_eq!(&lifted.public_inputs[..USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT], statement.as_slice());
            aggregate.circuit_data.verify(lifted.clone()).unwrap();
            lifted
        }).collect();
        let singleton = reward_root(&root, &fixture, 1, proofs[0].clone());
        assert_eq!(singleton.public_inputs[11], F::ONE);
        let first_pair = pair(&aggregate, proofs[0].clone(), proofs[1].clone());
        let left_heavy = pair(&aggregate, first_pair.clone(), proofs[2].clone());
        let right_heavy = pair(&aggregate, proofs[0].clone(), pair(&aggregate, proofs[1].clone(), proofs[2].clone()));
        assert_eq!(&left_heavy.public_inputs[..USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT], &right_heavy.public_inputs[..USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT]);
        for (proof, count, payout) in [(first_pair, 2, 3), (left_heavy, 3, 4), (right_heavy.clone(), 3, 4), (pair(&aggregate, right_heavy, proofs[3].clone()), 4, 6)] {
            aggregate.circuit_data.verify(proof.clone()).unwrap();
            let paid = reward_root(&root, &fixture, 1, proof);
            assert_eq!(paid.public_inputs.len(), 23);
            assert_eq!(paid.public_inputs[9], F::from_canonical_u32(10));
            assert_eq!(paid.public_inputs[10], F::from_canonical_u32(count));
            assert_eq!(paid.public_inputs[11], F::from_canonical_u32(payout));
            assert!(paid.public_inputs[13..19].iter().all(|limb| *limb == F::ZERO));
            root.circuit_data.verify(paid).unwrap();
        }
    }

    #[test]
    fn leaf_rejects_reward_owner_coordinate_and_nullifier_tampering() {
        let leaf = UserRewardLeafCircuit::new();
        let mut fixture = Fixture::new();
        let input = fixture.node(10, 0);
        for mutation in 0..7 {
            let mut bad = input.clone();
            match mutation {
                0 => bad.checkpoint_leaf.stats.pm_rewards_commitment.gutas_root.0.elements[0] += F::ONE,
                1 => bad.job.tag.tag_preimage.0.elements[0] += F::ONE,
                2 => bad.job.tag.siblings[0].0.elements[0] += F::ONE,
                3 => bad.nullifier_siblings[0].elements[0] += F::ONE,
                4 => bad.old_nullifier_root.elements[0] += F::ONE,
                5 => bad.job.path_index = 16,
                _ => bad.job.height = 1,
            }
            assert!(leaf.prove(&bad).is_err(), "leaf mutation {mutation}");
        }
        assert!(leaf.prove(&fixture.node(10, 0)).is_err());
    }

    #[test]
    fn aggregate_rejects_duplicate_subtrees_and_mismatched_common_fields_in_circuit() {
        let leaf = UserRewardLeafCircuit::new();
        let aggregate = UserRewardAggregateCircuit::new(&leaf);
        let mut fixture = Fixture::new();
        let first = lift(&aggregate, leaf.prove(&fixture.node(10, 0)).unwrap());
        let second = lift(&aggregate, leaf.prove(&fixture.node(10, 1)).unwrap());
        let valid = UserRewardAggregateWitness::Pair { left: first.clone(), right: second.clone() };
        let mut changed_leaf = fixture.node(10, 3);
        changed_leaf.checkpoint_leaf.stats.guta_fees_collected += F::ONE;
        let replacements = [
            first.clone(),
            lift(&aggregate, leaf.prove(&fixture.node(11, 2)).unwrap()),
            lift(&aggregate, leaf.prove(&Fixture::for_user(8, 12).node(10, 2)).unwrap()),
            lift(&aggregate, leaf.prove(&changed_leaf).unwrap()),
        ];
        for replacement in replacements {
            let mut witness = aggregate.set_witness(&valid).unwrap();
            let mut changed = PartialWitness::new();
            changed.set_proof_with_pis_target(&aggregate.targets.child_proofs[1], &replacement).unwrap();
            witness.target_values.extend(changed.target_values);
            assert!(aggregate.circuit_data.prove(witness).is_err());
        }
        for offset in [USER_REWARD_USER, USER_REWARD_SOURCE, USER_REWARD_SOURCE_LEAF_HASH, USER_REWARD_COUNT, USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT] {
            let mut witness = aggregate.set_witness(&valid).unwrap();
            let target = aggregate.targets.child_proofs[1].public_inputs[offset];
            witness.target_values.insert(target, second.public_inputs[offset] + F::ONE);
            assert!(aggregate.circuit_data.prove(witness).is_err());
        }
    }

    #[test]
    fn root_rejects_nonempty_start_and_source_tampering() {
        let leaf = UserRewardLeafCircuit::new();
        let aggregate = UserRewardAggregateCircuit::new(&leaf);
        let root = UserRewardRootCircuit::new(&aggregate);
        let mut fixture = Fixture::new();
        let first = lift(&aggregate, leaf.prove(&fixture.node(10, 0)).unwrap());
        let second = lift(&aggregate, leaf.prove(&fixture.node(10, 1)).unwrap());
        assert!(root.prove(&root_witness(&fixture, 1, second)).is_err());
        let input = root_witness(&fixture, 1, first);
        let proof = root.prove(&input).unwrap();
        for offset in [1, 9, 10, 11, 19] {
            let mut bad = proof.clone();
            bad.public_inputs[offset] += F::ONE;
            assert!(root.circuit_data.verify(bad).is_err());
        }
        for mutation in 0..6 {
            let mut bad = input.clone();
            match mutation {
                0 => bad.aggregate_proof.public_inputs[USER_REWARD_NEW] += F::ONE,
                1 => bad.aggregate_proof.public_inputs[USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT] += F::ONE,
                2 => bad.recipient[5] = 1,
                3 => bad.checkpoint_siblings[0].elements[0] += F::ONE,
                4 => bad.checkpoint_leaf.stats.guta_fees_collected += F::ONE,
                _ => bad.checkpoint_tree_root.elements[0] += F::ONE,
            }
            assert!(root.prove(&bad).is_err(), "root mutation {mutation}");
        }
        for (target, value) in [(root.targets.amount[0], F::from_canonical_u32(9)), (root.targets.remainder.low.0, F::ONE)] {
            let mut witness = root.set_witness(&input).unwrap();
            witness.target_values.insert(target, value);
            assert!(root.circuit_data.prove(witness).is_err());
        }
    }

    #[test]
    fn root_rejects_high_recipient_and_public_redirect() {
        let leaf = UserRewardLeafCircuit::new();
        let aggregate = UserRewardAggregateCircuit::new(&leaf);
        let root = UserRewardRootCircuit::new(&aggregate);
        let mut fixture = Fixture::new();
        let proved = lift(&aggregate, leaf.prove(&fixture.node(10, 0)).unwrap());
        let honest = root_witness(&fixture, 1, proved);
        let accepted = root.prove(&honest).unwrap();
        root.circuit_data.verify(accepted.clone()).unwrap();
        assert_eq!(accepted.public_inputs[0].to_canonical_u64(), u64::from(fixture.user_id));
        assert!(root.prove(&UserRewardRootWitness { recipient: [9, 2, 3, 4, 5, 1, 0, 0], ..honest.clone() }).is_err());
        assert_eq!(accepted.public_inputs[1], F::ONE);
        assert!(accepted.public_inputs[6..9].iter().all(|limb| *limb == F::ZERO));
        let chosen = root.prove(&UserRewardRootWitness { recipient: [9, 2, 3, 4, 5, 0, 0, 0], ..honest }).unwrap();
        root.circuit_data.verify(chosen.clone()).unwrap();
        assert_eq!(&chosen.public_inputs[1..9], &[F::from_canonical_u32(9), F::from_canonical_u32(2), F::from_canonical_u32(3), F::from_canonical_u32(4), F::from_canonical_u32(5), F::ZERO, F::ZERO, F::ZERO]);
        assert_ne!(chosen.public_inputs[1], accepted.public_inputs[1]);
        let mut redirected = chosen;
        redirected.public_inputs[1] = F::from_canonical_u32(8);
        assert!(root.circuit_data.verify(redirected).is_err());
    }

    #[test]
    fn source_leaf_hash_is_bound_and_missing_sources_are_rejected() {
        let leaf = UserRewardLeafCircuit::new();
        let aggregate = UserRewardAggregateCircuit::new(&leaf);
        let root = UserRewardRootCircuit::new(&aggregate);
        let mut fixture = Fixture::new();
        let original = fixture.node(10, 0);
        let proof = leaf.prove(&original).unwrap();
        assert_eq!(hash_value(&proof.public_inputs, USER_REWARD_SOURCE_LEAF_HASH), original.checkpoint_leaf.qfhash::<PoseidonHash>().0);
        let mut forged = original.clone();
        forged.checkpoint_leaf.stats.guta_fees_collected += F::ONE;
        let forged_proof = lift(&aggregate, leaf.prove(&forged).unwrap());
        let mut input = root_witness(&fixture, 1, forged_proof);
        assert!(root.prove(&input).is_err());
        input.checkpoint_leaf = forged.checkpoint_leaf;
        assert!(root.prove(&input).is_err());
        let mut other_source = original;
        other_source.job.source_checkpoint_id = 9;
        let other = lift(&aggregate, leaf.prove(&other_source).unwrap());
        assert!(root.prove(&root_witness(&fixture, 1, other)).is_err());
    }

    #[test]
    fn exact_payout_enforces_integer_identity_and_bounds() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let count = builder.add_virtual_target();
        let fees = U64Limbs { low: builder.add_virtual_u32_target(), high: builder.add_virtual_u32_target() };
        let completed = U64Limbs { low: builder.add_virtual_u32_target(), high: builder.add_virtual_u32_target() };
        let (amount, remainder) = exact_payout(&mut builder, count, fees, completed);
        let circuit = builder.build::<C>();
        let prove = |count_value: u32, fee_value: u64, completed_value: u64, amount_value: u64, remainder_value: u64| {
            let mut witness = PartialWitness::new();
            witness.set_target(count, F::from_canonical_u32(count_value)).unwrap();
            for (targets, value) in [(fees, fee_value), (completed, completed_value), (amount, amount_value), (remainder, remainder_value)] {
                witness.set_target(targets.low.0, F::from_canonical_u32(value as u32)).unwrap();
                witness.set_target(targets.high.0, F::from_canonical_u32((value >> 32) as u32)).unwrap();
            }
            circuit.prove(witness)
        };
        for (count, fees, completed) in [(1, 0, 1), (3, 100, 64), (1, 0xffff_ffff_0000_0000, 1), (u32::MAX, 0xffff_fffe_ffff_ffff, u64::from(u32::MAX)), (u32::MAX, 0xffff_fffe_ffff_ffff, 0xffff_ffff_0000_0000)] {
            let numerator = u128::from(count) * u128::from(fees);
            let quotient = (numerator / u128::from(completed)) as u64;
            let remainder = (numerator % u128::from(completed)) as u64;
            circuit.verify(prove(count, fees, completed, quotient, remainder).unwrap()).unwrap();
        }
        for values in [(0, 100, 64, 0, 0), (1, 100, 0, 0, 0), (2, 100, 1, 200, 0), (3, 100, 64, 3, 108), (3, 100, 64, 5, 0), (3, 100, 64, 4, 43), (1, 0xffff_ffff_0000_0001, 1, 0xffff_ffff_0000_0001, 0), (1, 1, 0xffff_ffff_0000_0000, 0xffff_ffff_0000_0000, 0xffff_fffe_ffff_ffff)] {
            assert!(prove(values.0, values.1, values.2, values.3, values.4).is_err());
        }
    }

    #[test]
    fn checked_products_retain_high_half_and_reject_noncanonical_limbs() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let low = builder.add_virtual_target();
        let high = builder.add_virtual_target();
        let value = U64Limbs { low: U32Target(low), high: U32Target(high) };
        canonical_limbs(&mut builder, value);
        let product = product_u64(&mut builder, value, value);
        builder.register_public_inputs(&product.map(|limb| limb.0));
        let data = builder.build::<C>();
        let number = 0xffff_fffe_ffff_ffffu64;
        let mut witness = PartialWitness::new();
        witness.set_target(low, F::from_canonical_u32(number as u32)).unwrap();
        witness.set_target(high, F::from_canonical_u32((number >> 32) as u32)).unwrap();
        let proof = data.prove(witness).unwrap();
        let square = u128::from(number) * u128::from(number);
        for index in 0..4 { assert_eq!(proof.public_inputs[index].to_canonical_u64(), ((square >> (index * 32)) & 0xffff_ffff) as u64); }
        let mut witness = PartialWitness::new();
        witness.set_target(low, F::ONE).unwrap();
        witness.set_target(high, F::from_canonical_u32(u32::MAX)).unwrap();
        assert!(data.prove(witness).is_err());
    }

    #[test]
    fn authenticated_zero_denominator_and_excess_count_are_rejected_at_root() {
        let leaf = UserRewardLeafCircuit::new();
        let aggregate = UserRewardAggregateCircuit::new(&leaf);
        let root = UserRewardRootCircuit::new(&aggregate);
        for completed in [0, 1] {
            let mut fixture = Fixture::new();
            fixture.checkpoint.stats.pm_jobs_completed.gutas_completed = F::from_canonical_u32(completed);
            fixture.checkpoints.insert(10, fixture.checkpoint.qfhash::<PoseidonHash>().0);
            let first = lift(&aggregate, leaf.prove(&fixture.node(10, 0)).unwrap());
            let second = lift(&aggregate, leaf.prove(&fixture.node(10, 1)).unwrap());
            let proof = pair(&aggregate, first, second);
            assert!(root.prove(&root_witness(&fixture, 1, proof)).is_err());
        }
    }

    #[test]
    fn leaf_and_aggregate_verifier_identities_are_pinned() {
        let leaf = UserRewardLeafCircuit::new();
        let aggregate = UserRewardAggregateCircuit::new(&leaf);
        let mut fixture = Fixture::new();
        let proof = leaf.prove(&fixture.node(10, 0)).unwrap();
        let input = UserRewardAggregateWitness::Leaf { leaf: proof };
        let mut witness = aggregate.set_witness(&input).unwrap();
        let mut changed = PartialWitness::new();
        changed.set_verifier_data_target(&aggregate.targets.pinned_aggregate, &leaf.circuit_data.verifier_only).unwrap();
        witness.target_values.extend(changed.target_values);
        assert!(aggregate.circuit_data.prove(witness).is_err());
        let mut witness = aggregate.set_witness(&input).unwrap();
        let mut changed = PartialWitness::new();
        changed.set_proof_with_pis_target(&aggregate.targets.leaf_proof, &aggregate.dummy_leaf_proof).unwrap();
        witness.target_values.extend(changed.target_values);
        assert!(aggregate.circuit_data.prove(witness).is_err());
    }

    use std::collections::BTreeMap;

    pub(in crate::bridge::circuits) type Leaves = BTreeMap<u64, HashOut<F>>;

    pub(in crate::bridge::circuits) fn path<const H: usize>(leaves: &Leaves, mut index: u64, mut empty: HashOut<F>) -> ([HashOut<F>; H], HashOut<F>) {
        let mut nodes = leaves.clone();
        let siblings = std::array::from_fn(|_| {
            let sibling = nodes.get(&(index ^ 1)).copied().unwrap_or(empty);
            let mut parents = BTreeMap::new();
            for &child in nodes.keys() {
                parents.insert(child >> 1, PoseidonHash::two_to_one(
                    nodes.get(&(child & !1)).copied().unwrap_or(empty),
                    nodes.get(&(child | 1)).copied().unwrap_or(empty),
                ));
            }
            nodes = parents;
            empty = PoseidonHash::two_to_one(empty, empty);
            index >>= 1;
            sibling
        });
        (siblings, nodes.get(&0).copied().unwrap_or(empty))
    }

    #[test]
    fn coordinate_extremes_bind_the_full_twenty_bit_index() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let user_id = builder.add_virtual_target();
        let coordinates = RewardJobCoordinates {
            user_id, height: builder.add_virtual_target(), path_index: builder.add_virtual_target(),
            nullifier_index: builder.add_virtual_target(),
        };
        let tag = UserRewardTagTarget::new(&mut builder, &coordinates);
        let nullifier = RewardNullifierTargets::add(&mut builder);
        builder.connect(nullifier.index, coordinates.nullifier_index);
        builder.register_public_input(coordinates.nullifier_index);
        let circuit = builder.build::<C>();
        let preimage = QHashOut::from_values(7, 0, 4, 8);
        let tag_input = UserRewardTagWitness {
            tag_preimage: preimage, leaf_left: QHashOut::ZERO, leaf_right: QHashOut::ZERO,
            leaf_tag: QHashOut(PoseidonHash::two_to_one(preimage.0, preimage.0)),
            siblings: [QHashOut::ZERO; MAX_REWARD_HEIGHT], parent_tags: [QHashOut::ZERO; MAX_REWARD_HEIGHT],
        };
        let prove = |user: u32, height: u32, path_index: u32, index: u32, input: &UserRewardTagWitness| {
            let mut witness = PartialWitness::new();
            witness.set_target(coordinates.user_id, F::from_canonical_u32(user)).unwrap();
            witness.set_target(coordinates.height, F::from_canonical_u32(height)).unwrap();
            witness.set_target(coordinates.path_index, F::from_canonical_u32(path_index)).unwrap();
            tag.set_witness(&mut witness, input).unwrap();
            nullifier.set_witness(&mut witness, index, &[HashOut::ZERO; 20]).unwrap();
            circuit.prove(witness)
        };
        for (height, path, index) in [(2, 0, 0), (21, (1 << 19) - 1, (1 << 20) - 2)] {
            let proof = prove(7, height, path, index, &tag_input).unwrap();
            assert_eq!(proof.public_inputs[0], F::from_canonical_u32(index));
            circuit.verify(proof).unwrap();
        }
        for (height, path, index) in [(1, 0, 0), (22, 0, 0), (2, 1, 1), (21, 1 << 19, (1 << 20) - 1), (21, 0, (1 << 19) - 1 + (1 << 20))] {
            assert!(prove(7, height, path, index, &tag_input).is_err());
        }
        let zero_user_preimage = QHashOut::from_values(0, 0, 4, 8);
        let zero_user_input = UserRewardTagWitness {
            tag_preimage: zero_user_preimage, leaf_left: QHashOut::ZERO, leaf_right: QHashOut::ZERO,
            leaf_tag: QHashOut(PoseidonHash::two_to_one(zero_user_preimage.0, zero_user_preimage.0)),
            siblings: [QHashOut::ZERO; MAX_REWARD_HEIGHT], parent_tags: [QHashOut::ZERO; MAX_REWARD_HEIGHT],
        };
        circuit.verify(prove(0, 2, 0, 0, &zero_user_input).unwrap()).unwrap();
        let zero_preimage = QHashOut::ZERO;
        let zero_tag = PoseidonHash::two_to_one(zero_preimage.0, zero_preimage.0);
        // Poseidon(ZERO,ZERO) must be nonzero per limb, else the leaf-tag guard would reject instead.
        assert!(zero_tag.elements.iter().all(|limb| *limb != F::ZERO));
        let zero_input = UserRewardTagWitness {
            tag_preimage: zero_preimage, leaf_left: QHashOut::ZERO, leaf_right: QHashOut::ZERO,
            leaf_tag: QHashOut(zero_tag),
            siblings: [QHashOut::ZERO; MAX_REWARD_HEIGHT], parent_tags: [QHashOut::ZERO; MAX_REWARD_HEIGHT],
        };
        assert!(prove(0, 2, 0, 0, &zero_input).is_err());
    }

    #[test]
    fn aggregate_count_addition_rejects_overflow() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let left = builder.add_virtual_target();
        let right = builder.add_virtual_target();
        builder.range_check(left, 32);
        builder.range_check(right, 32);
        let sum = checked_add_u32(&mut builder, left, right);
        builder.register_public_input(sum);
        let circuit = builder.build::<C>();
        for (a, b, accepted) in [(u32::MAX - 1, 1, true), (u32::MAX, 1, false)] {
            let mut witness = PartialWitness::new();
            witness.set_target(left, F::from_canonical_u32(a)).unwrap();
            witness.set_target(right, F::from_canonical_u32(b)).unwrap();
            assert_eq!(circuit.prove(witness).is_ok(), accepted);
        }
    }

    #[test]
    fn fixed_statement_and_tree_dimensions() {
        assert_eq!(USER_REWARD_LEAF_PUBLIC_INPUT_COUNT, 15);
        assert_eq!(USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT + USER_REWARD_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT, 83);
        assert_eq!(USER_REWARD_ROOT_PUBLIC_INPUT_COUNT, 23);
        assert_eq!(REWARD_NULLIFIER_HEIGHT, 20);
        assert_eq!(path::<20>(&Leaves::new(), 0, HashOut::ZERO).1, *REWARD_NULLIFIER_EMPTY_ROOT);
    }
}
