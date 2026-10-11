use hashbrown::HashMap;

use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    gates::noop::NoopGate,
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
use psy_client_data::qdata::{
    checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf},
    user::PsyUserLeaf,
};
use psy_common_circuit::{
    builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore},
    circuits::zk_signature3::core::PsyBasicZKSignatureCircuit,
    traits::CreatableTarget,
    u32::arithmetic_u32::{CircuitBuilderU32, U32Target},
};
use psy_config::network_constants::{CHECKPOINT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT};
use psy_network_circuit::gadgets::qdata::{
    checkpoint::PsyCheckpointLeafGadget,
    checkpoint_state_roots::PsyCheckpointGlobalStateRootsGadget,
    user::PsyUserLeafGadget,
};
use psy_plonky2_basic_helpers::builder::{
    core::CircuitBuilderHelpersCore,
    pad_circuit::CircuitBuilderQEDCommonGates,
    select::CircuitBuilderSelectHelpers,
};
use psy_plonky2_common_circuits::hash::merkle::gadgets::{merkle_proof::{MerkleProofGadget, OptionalMerkleProofGadget}, delta_merkle_proof::DeltaMerkleProofGadget};
use psy_ups_circuit::signature::software_defined::get_zk_public_key_param;

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
pub struct RewardTagWitness {
    pub tag_preimage: QHashOut<F>,
    pub leaf_left: QHashOut<F>,
    pub leaf_right: QHashOut<F>,
    pub leaf_tag: QHashOut<F>,
    pub siblings: [QHashOut<F>; MAX_REWARD_HEIGHT],
    pub parent_tags: [QHashOut<F>; MAX_REWARD_HEIGHT],
}

pub struct RewardTagTarget {
    pub tag_preimage: HashOutTarget,
    pub leaf_left: HashOutTarget,
    pub leaf_right: HashOutTarget,
    pub leaf_tag: HashOutTarget,
    pub siblings: [HashOutTarget; MAX_REWARD_HEIGHT],
    pub parent_tags: [HashOutTarget; MAX_REWARD_HEIGHT],
    pub root: HashOutTarget,
}

impl RewardTagTarget {
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
        for (index, height) in (2..=MAX_REWARD_HEIGHT).enumerate() {
            offset = builder.mul_const_add(F::from_canonical_u32((1u32 << height) - 1), heights[index].target, offset);
        }
        let nullifier = builder.add(offset, reward.path_index);
        builder.connect(reward.nullifier_index, nullifier);
        builder.range_check(reward.nullifier_index, 32);
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
        builder.assert_non_zero_hash(tag_preimage);
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

    pub(super) fn set_witness(&self, witness: &mut PartialWitness<F>, input: &RewardTagWitness) -> anyhow::Result<()> {
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
        RewardNullifierSourceWitness, RewardNullifierSourceTargets,
        REWARD_NULLIFIER_EMPTY_LEAF, REWARD_NULLIFIER_INNER_HEIGHT,
        REWARD_NULLIFIER_OUTER_HEIGHT,
    },
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

pub const REWARD_LEAF_CAPACITY: usize = 16;
pub const REWARD_SEGMENT_DEGREE_BITS: usize = 16;
pub const REWARD_MERGE_DEGREE_BITS: usize = 16;

pub const REWARD_SEGMENT_STATEMENT_LEN: usize = 22;
pub const REWARD_MERGE_STATEMENT_LEN: usize = 22;

pub const REWARD_ROOT_STATEMENT_LEN: usize = 30;

const SEGMENT_USER: usize = 0;
const SEGMENT_ANCHOR: usize = 1;
const SEGMENT_OLD: usize = 5;
const SEGMENT_NEW: usize = 9;
const SEGMENT_COUNT: usize = 13;
const SEGMENT_AMOUNT: usize = 14;

#[derive(Clone, Debug)]
pub struct AuthenticatedJobWitness {
    pub source_checkpoint_id: u32,
    pub height: u8,
    pub path_index: u32,
    pub tag: RewardTagWitness,
}

#[derive(Clone, Debug)]
pub struct RewardSegmentSourceWitness {
    pub source_checkpoint_id: u32,
    pub checkpoint_leaf: PsyCheckpointLeaf<F>,
    pub checkpoint_siblings: [HashOut<F>; CHECKPOINT_TREE_HEIGHT as usize],
    pub amount_limbs: [u32; 2],
    pub jobs: Vec<AuthenticatedJobWitness>,
    pub nullifier: RewardNullifierSourceWitness,
}

#[derive(Clone, Debug)]
pub struct RewardSegmentWitness {
    pub user_id: u32,
    pub anchor_checkpoint_id: u32,
    pub checkpoint_tree_root: HashOut<F>,
    pub old_nullifier_root: HashOut<F>,
    pub source: RewardSegmentSourceWitness,
}

#[derive(Clone, Debug)]
pub enum RewardMergeWitness {
    Leaf { segment: RewardSegmentProof },
    Pair { left: RewardMergeProof, right: RewardMergeProof },
}

#[derive(Clone, Debug)]
pub struct RewardRootWitness {
    pub recipient: [u32; 8],
    pub anchor_checkpoint_id: u32,
    pub anchor_leaf: PsyCheckpointLeaf<F>,
    pub anchor_siblings: [HashOut<F>; CHECKPOINT_TREE_HEIGHT as usize],
    pub global_roots: PsyCheckpointGlobalStateRoots<F>,
    pub user_leaf: PsyUserLeaf<F>,
    pub user_siblings: [HashOut<F>; GLOBAL_USER_TREE_HEIGHT as usize],
    pub private_key: HashOut<F>,
    pub merge_proof: RewardMergeProof,
}

pub type RewardSegmentProof = ProofWithPublicInputs<F, C, D>;
pub type RewardMergeProof = ProofWithPublicInputs<F, C, D>;
pub type RewardRootProof = ProofWithPublicInputs<F, C, D>;

#[derive(Clone, Copy)]
struct U64Limbs { low: U32Target, high: U32Target }

struct JobTargets {
    source: Target, height: Target, path_index: Target, coordinate: Target,
    tag: RewardTagTarget, gutas_root: HashOutTarget, active: BoolTarget,
}

struct SourceTargets {
    membership: HistoricalMerkleProofTarget,
    amount: U64Limbs,
    nullifier: RewardNullifierSourceTargets,
}

pub struct RewardSegmentTargets {
    pub active_len: Target,
    pub user_id: Target,
    pub anchor_checkpoint_id: Target,
    pub checkpoint_tree_root: HashOutTarget,
    pub old_nullifier_root: HashOutTarget,
    pub new_nullifier_root: HashOutTarget,
    pub count: Target,
    pub amount: [U32Target; 8],
    jobs: Vec<JobTargets>,
    source: SourceTargets,
}

pub struct RewardMergeTargets {
    pub is_leaf: BoolTarget,
    pub is_pair: BoolTarget,
    pub user_id: Target,
    pub checkpoint_tree_root: HashOutTarget,
    pub old_nullifier_root: HashOutTarget,
    pub new_nullifier_root: HashOutTarget,
    pub count: Target,
    pub amount: [U32Target; 8],
    segment_proof: ProofWithPublicInputsTarget<D>,
    inactive_segment_proof: ProofWithPublicInputsTarget<D>,
    child_proofs: [ProofWithPublicInputsTarget<D>; 2],
    pinned_merge: VerifierCircuitTarget,
}

pub struct RewardRootTargets {
    pub user_id: Target,
    pub recipient: [Target; 8],
    pub old_nullifier_root: HashOutTarget,
    pub new_nullifier_root: HashOutTarget,
    pub count: Target,
    pub amount: [Target; 8],
    pub checkpoint_tree_root: HashOutTarget,
    anchor: HistoricalMerkleProofTarget,
    global_roots: PsyCheckpointGlobalStateRootsGadget,
    user: PsyUserLeafGadget,
    user_path: MerkleProofGadget,
    private_key: HashOutTarget,
    merge_proof: ProofWithPublicInputsTarget<D>,
}

pub struct RewardSegmentCircuit {
    pub targets: RewardSegmentTargets,
    pub circuit_data: CircuitData<F, C, D>,
    pub fingerprint: QHashOut<F>,
}

pub struct RewardMergeCircuit {
    pub targets: RewardMergeTargets,
    pub circuit_data: CircuitData<F, C, D>,
    pub fingerprint: QHashOut<F>,
    segment_verifier: VerifierOnlyCircuitData<C, D>,
    segment_common: CommonCircuitData<F, D>,
    dummy_segment_proof: ProofWithPublicInputs<F, C, D>,
    seed: SegmentSeedTargets,
}

pub struct RewardRootCircuit {
    pub targets: RewardRootTargets,
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

fn add_amount(builder: &mut CircuitBuilder<F, D>, left: &[U32Target; 8], right: &[U32Target; 8]) -> [U32Target; 8] {
    let mut carry = builder.zero_u32();
    let mut sum = [builder.zero_u32(); 8];
    for index in 0..8 {
        let (limb, first_carry) = builder.add_u32(left[index], right[index]);
        let (with_carry, second_carry) = builder.add_u32(limb, carry);
        let (carry_sum, overflow) = builder.add_u32(first_carry, second_carry);
        builder.assert_zero_u32(overflow);
        sum[index] = with_carry;
        carry = carry_sum;
    }
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

fn counted_job(builder: &mut CircuitBuilder<F, D>, user_id: Target, active: BoolTarget) -> JobTargets {
    let source = builder.add_virtual_target();
    builder.range_check(source, 32);
    let reward = RewardJobCoordinates {
        user_id,
        height: builder.add_virtual_target(),
        path_index: builder.add_virtual_target(),
        nullifier_index: builder.add_virtual_target(),
    };
    let tag = RewardTagTarget::new(builder, &reward);
    let gutas_root = tag.root;
    JobTargets {
        source, height: reward.height, path_index: reward.path_index, coordinate: reward.nullifier_index,
        tag, gutas_root, active,
    }
}

fn segment_statement(targets: &RewardSegmentTargets) -> Vec<Target> {
    let mut fields = vec![targets.user_id];
    fields.extend(targets.checkpoint_tree_root.elements);
    fields.extend(targets.old_nullifier_root.elements);
    fields.extend(targets.new_nullifier_root.elements);
    fields.push(targets.count);
    fields.extend(targets.amount.map(|limb| limb.0));
    assert_eq!(fields.len(), REWARD_SEGMENT_STATEMENT_LEN);
    fields
}


struct SegmentSeedTargets {
    user: Target,
    job: JobTargets,
    membership: HistoricalMerkleProofTarget,
    amount_value: Target,
    inner: DeltaMerkleProofGadget,
    outer: DeltaMerkleProofGadget,
}

impl SegmentSeedTargets {
    fn set_witness(&self, witness: &mut PartialWitness<F>) -> anyhow::Result<()> {
        // Live gate-set seed gadgets do not bind business inputs, but still need witnesses.
        witness.set_bool_target(self.job.active, false)?;
        witness.set_target(self.user, F::from_canonical_u32(7))?;
        witness.set_target(self.job.source, F::ZERO)?;
        witness.set_target(self.job.height, F::TWO)?;
        witness.set_target(self.job.path_index, F::ZERO)?;
        let tag_preimage = QHashOut::from_values(7, 1, 2, 3);
        self.job.tag.set_witness(witness, &RewardTagWitness {
            tag_preimage,
            leaf_left: QHashOut::ZERO,
            leaf_right: QHashOut::ZERO,
            leaf_tag: QHashOut(PoseidonHash::two_to_one(tag_preimage.0, tag_preimage.0)),
            siblings: [QHashOut::ZERO; MAX_REWARD_HEIGHT],
            parent_tags: [QHashOut::ZERO; MAX_REWARD_HEIGHT],
        })?;
        witness.set_target(self.membership.end_checkpoint_id[0], F::ZERO)?;
        self.membership.checkpoint_leaf.set_witness(witness, &PsyCheckpointLeaf::default())?;
        for &sibling in &self.membership.path.siblings {
            witness.set_hash_target(sibling, HashOut::ZERO)?;
        }
        witness.set_target(self.amount_value, F::ZERO)?;
        for delta in [&self.inner, &self.outer] {
            witness.set_target(delta.index, F::ZERO)?;
            witness.set_hash_target(delta.old_value, HashOut::ZERO)?;
            witness.set_hash_target(delta.new_value, HashOut::ZERO)?;
            for &sibling in &delta.siblings {
                witness.set_hash_target(sibling, HashOut::ZERO)?;
            }
        }
        Ok(())
    }
}

fn segment_seed(builder: &mut CircuitBuilder<F, D>) -> SegmentSeedTargets {
    builder.add_qed_type_d_common_gates();
    let zero = builder.zero();
    let active = builder.add_virtual_bool_target_safe();
    let user = builder.add_virtual_target();
    let job = counted_job(builder, user, active);
    let leaf = PsyCheckpointLeafGadget::create_virtual(builder);
    let root = builder.add_virtual_hash();
    let anchor = builder.add_virtual_target();
    let membership = historical_merkle_proof(builder, [job.source, zero], &leaf, [anchor, zero], root);
    let amount_value = builder.add_virtual_target();
    let value = canonical_u64(builder, amount_value);
    let product = product_u64(builder, value, value);
    assert_less_equal_u128(builder, &product, &product);
    let amount = [builder.zero_u32(); 8];
    let _ = add_amount(builder, &amount, &amount);
    let inner = DeltaMerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(builder, REWARD_NULLIFIER_INNER_HEIGHT);
    let outer = DeltaMerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(builder, REWARD_NULLIFIER_OUTER_HEIGHT);
    SegmentSeedTargets { user, job, membership, amount_value, inner, outer }
}

fn build_segment() -> RewardSegmentCircuit {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let zero = builder.zero();
    let one = builder.one();
    let active_len = builder.add_virtual_target();
    builder.range_check(active_len, 8);
    let in_range = builder.is_less_than_or_equal(8, one, active_len);
    let capacity = builder.constant(F::from_canonical_usize(REWARD_LEAF_CAPACITY));
    let below_capacity = builder.is_less_than_or_equal(8, active_len, capacity);
    let valid_count = builder.and(in_range, below_capacity);
    builder.assert_one(valid_count.target);

    let user_id = builder.add_virtual_target();
    builder.range_check(user_id, 32);
    let anchor_checkpoint_id = builder.add_virtual_target();
    builder.range_check(anchor_checkpoint_id, 32);
    let checkpoint_tree_root = builder.add_virtual_hash();
    let old_nullifier_root = builder.add_virtual_hash();

    let jobs: Vec<_> = (0..REWARD_LEAF_CAPACITY).map(|index| {
        let slot = builder.constant(F::from_canonical_usize(index));
        let active = builder.is_less_than(8, slot, active_len);
        counted_job(&mut builder, user_id, active)
    }).collect();
    for pair in jobs.windows(2) {
        builder.connect(pair[0].source, pair[1].source);
    }
    let source = jobs[0].source;
    let leaf = PsyCheckpointLeafGadget::create_virtual(&mut builder);
    let membership = historical_merkle_proof(&mut builder, [source, zero], &leaf, [anchor_checkpoint_id, zero], checkpoint_tree_root);
    let completed = canonical_u64(&mut builder, leaf.stats.pm_jobs_completed.gutas_completed);
    let fees = canonical_u64(&mut builder, leaf.stats.guta_fees_collected);
    builder.assert_non_zero(leaf.stats.pm_jobs_completed.gutas_completed);
    let zero_u32 = U32Target(zero);
    assert_less_equal_u128(&mut builder, &[U32Target(active_len), zero_u32, zero_u32, zero_u32], &[completed.low, completed.high, zero_u32, zero_u32]);
    let source_amount = U64Limbs { low: U32Target(builder.add_virtual_target()), high: U32Target(builder.add_virtual_target()) };
    canonical_limbs(&mut builder, source_amount);
    let paid = product_u64(&mut builder, source_amount, completed);
    let available = product_u64(&mut builder, U64Limbs { low: U32Target(active_len), high: zero_u32 }, fees);
    assert_less_equal_u128(&mut builder, &paid, &available);
    let mut amount = [zero_u32; 8];
    amount[0] = source_amount.low;
    amount[1] = source_amount.high;
    let outer = DeltaMerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, REWARD_NULLIFIER_OUTER_HEIGHT);
    builder.connect(outer.index, source);
    builder.connect_hashes(outer.old_root, old_nullifier_root);
    let empty = builder.constant_hash(REWARD_NULLIFIER_EMPTY_LEAF);
    let occupied = builder.constant_hash(HashOut { elements: [F::ONE, F::ZERO, F::ZERO, F::ZERO] });
    let mut inner_root = outer.old_value;
    let mut inner = Vec::with_capacity(REWARD_LEAF_CAPACITY);
    for job in &jobs {
        builder.connect_hashes_if_true(job.active, job.gutas_root, leaf.stats.pm_rewards_commitment.gutas_root);
        let delta = DeltaMerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, REWARD_NULLIFIER_INNER_HEIGHT);
        builder.connect(delta.index, job.coordinate);
        builder.connect_hashes(delta.old_value, empty);
        let inserted = builder.select_hash(job.active, occupied, empty);
        builder.connect_hashes(delta.new_value, inserted);
        builder.connect_hashes_if_true(job.active, delta.old_root, inner_root);
        inner_root = builder.select_hash(job.active, delta.new_root, inner_root);
        inner.push(delta);
    }
    builder.connect_hashes(outer.new_value, inner_root);
    let new_nullifier_root = outer.new_root;
    let targets = RewardSegmentTargets {
        active_len, user_id, anchor_checkpoint_id, checkpoint_tree_root, old_nullifier_root,
        new_nullifier_root, count: active_len, amount, jobs,
        source: SourceTargets { membership, amount: source_amount, nullifier: RewardNullifierSourceTargets { outer, inner } },
    };
    builder.register_public_inputs(&segment_statement(&targets));
    let circuit_data = builder.build::<C>();
    assert_eq!(circuit_data.common.num_public_inputs, REWARD_SEGMENT_STATEMENT_LEN);
    let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
    RewardSegmentCircuit { targets, circuit_data, fingerprint }
}

fn merge_common_data(segment: &RewardSegmentCircuit) -> CommonCircuitData<F, D> {
    let config = CircuitConfig::standard_recursion_config();
    let mut stage = CircuitBuilder::<F, D>::new(config.clone());
    segment_seed(&mut stage);
    let _ = stage.add_virtual_proof_with_pis(&segment.circuit_data.common);
    let data = stage.build::<C>();

    let mut stage = CircuitBuilder::<F, D>::new(config.clone());
    segment_seed(&mut stage);
    let _ = stage.add_virtual_proof_with_pis(&segment.circuit_data.common);
    let proof = stage.add_virtual_proof_with_pis(&data.common);
    let verifier = stage.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    stage.verify_proof::<C>(&proof, &verifier, &data.common);
    let data = stage.build::<C>();

    let mut stage = CircuitBuilder::<F, D>::new(config);
    segment_seed(&mut stage);
    let _ = stage.add_virtual_proof_with_pis(&segment.circuit_data.common);
    let proof = stage.add_virtual_proof_with_pis(&data.common);
    let verifier = stage.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    stage.verify_proof::<C>(&proof, &verifier, &data.common);
    while stage.num_gates() < 1 << REWARD_MERGE_DEGREE_BITS { stage.add_gate(NoopGate, vec![]); }
    let common = stage.build::<C>().common;
    assert_eq!(common.config.fri_config.cap_height, 4);
    let mut child_common = common;
    child_common.num_public_inputs = REWARD_MERGE_STATEMENT_LEN + 4 + 4 * 16;
    child_common
}


fn connect_if(builder: &mut CircuitBuilder<F, D>, condition: BoolTarget, left: Target, right: Target) {
    let selected = builder.select(condition, left, right);
    builder.connect(selected, right);
}

fn build_merge(segment: &RewardSegmentCircuit) -> RewardMergeCircuit {
    let child_common = merge_common_data(segment);
    let segment_dummy = plonky2::recursion::dummy_circuit::dummy_circuit::<F, C, D>(&segment.circuit_data.common);
    let dummy_segment_proof = plonky2::recursion::dummy_circuit::dummy_proof::<F, C, D>(&segment_dummy, HashMap::new()).expect("reward segment dummy");
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let seed = segment_seed(&mut builder);
    let one = builder.one();
    let is_leaf = builder.add_virtual_bool_target_safe();
    let is_pair = builder.add_virtual_bool_target_safe();
    let exclusive_mode = builder.add(is_leaf.target, is_pair.target);
    builder.connect(exclusive_mode, one);

    let segment_proof = builder.add_virtual_proof_with_pis(&segment.circuit_data.common);
    let pinned_segment = builder.constant_verifier_data(&segment.circuit_data.verifier_only);
    let (inactive_segment, inactive_segment_verifier) = builder
        .dummy_proof_and_constant_vk_no_generator::<C>(&segment.circuit_data.common)
        .expect("reward merge inactive segment proof");
    builder.conditionally_verify_proof::<C>(
        is_leaf, &segment_proof, &pinned_segment, &inactive_segment, &inactive_segment_verifier,
        &segment.circuit_data.common,
    );
    let child_proofs = [
        builder.add_virtual_proof_with_pis(&child_common),
        builder.add_virtual_proof_with_pis(&child_common),
    ];
    let user_id = builder.add_virtual_target();
    let checkpoint_tree_root = builder.add_virtual_hash();
    let old_nullifier_root = builder.add_virtual_hash();
    let new_nullifier_root = builder.add_virtual_hash();
    let count = builder.add_virtual_target();
    let amount = std::array::from_fn(|_| builder.add_virtual_u32_target());
    let mut fields = vec![user_id];
    fields.extend(checkpoint_tree_root.elements);
    fields.extend(old_nullifier_root.elements);
    fields.extend(new_nullifier_root.elements);
    fields.push(count);
    fields.extend(amount.map(|limb| limb.0));
    assert_eq!(fields.len(), REWARD_MERGE_STATEMENT_LEN);
    builder.register_public_inputs(&fields);
    let pinned_merge = builder.add_verifier_data_public_inputs();
    let targets = RewardMergeTargets {
        is_leaf, is_pair, user_id, checkpoint_tree_root, old_nullifier_root, new_nullifier_root,
        count, amount, segment_proof, inactive_segment_proof: inactive_segment, child_proofs, pinned_merge,
    };
    for child in &targets.child_proofs {
        builder.conditionally_verify_cyclic_proof_or_dummy::<C>(is_pair, child, &child_common).expect("reward merge cyclic verifier");
    }

    let segment_inputs = &targets.segment_proof.public_inputs;
    let left = &targets.child_proofs[0].public_inputs;
    let right = &targets.child_proofs[1].public_inputs;
    connect_if(&mut builder, is_leaf, segment_inputs[SEGMENT_USER], user_id);
    connect_if(&mut builder, is_pair, left[SEGMENT_USER], user_id);
    connect_if(&mut builder, is_pair, right[SEGMENT_USER], user_id);
    for index in 0..4 {
        connect_if(&mut builder, is_leaf, segment_inputs[SEGMENT_ANCHOR + index], checkpoint_tree_root.elements[index]);
        connect_if(&mut builder, is_pair, left[SEGMENT_ANCHOR + index], checkpoint_tree_root.elements[index]);
        connect_if(&mut builder, is_pair, right[SEGMENT_ANCHOR + index], checkpoint_tree_root.elements[index]);
        connect_if(&mut builder, is_leaf, segment_inputs[SEGMENT_OLD + index], old_nullifier_root.elements[index]);
        connect_if(&mut builder, is_leaf, segment_inputs[SEGMENT_NEW + index], new_nullifier_root.elements[index]);
        connect_if(&mut builder, is_pair, left[SEGMENT_OLD + index], old_nullifier_root.elements[index]);
        connect_if(&mut builder, is_pair, right[SEGMENT_NEW + index], new_nullifier_root.elements[index]);
        connect_if(&mut builder, is_pair, left[SEGMENT_NEW + index], right[SEGMENT_OLD + index]);
    }
    connect_if(&mut builder, is_leaf, segment_inputs[SEGMENT_COUNT], count);
    let pair_count = checked_add_u32(&mut builder, left[SEGMENT_COUNT], right[SEGMENT_COUNT]);
    connect_if(&mut builder, is_pair, pair_count, count);
    for index in 0..8 {
        connect_if(&mut builder, is_leaf, segment_inputs[SEGMENT_AMOUNT + index], amount[index].0);
    }
    let left_amount = std::array::from_fn(|index| U32Target(left[SEGMENT_AMOUNT + index]));
    let right_amount = std::array::from_fn(|index| U32Target(right[SEGMENT_AMOUNT + index]));
    let pair_amount = add_amount(&mut builder, &left_amount, &right_amount);
    for index in 0..8 { connect_if(&mut builder, is_pair, pair_amount[index].0, amount[index].0); }

    while builder.num_gates() < 1 << REWARD_MERGE_DEGREE_BITS { builder.add_gate(NoopGate, vec![]); }
    let (circuit_data, matches) = builder.try_build_with_options::<C>(true);
    assert!(matches, "reward merge common data mismatch");
    assert_eq!(circuit_data.common.num_public_inputs, REWARD_MERGE_STATEMENT_LEN + 4 + 4 * 16);
    let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
    RewardMergeCircuit {
        targets,
        seed,
        fingerprint, circuit_data, segment_verifier: segment.circuit_data.verifier_only.clone(), segment_common: segment.circuit_data.common.clone(), dummy_segment_proof,
    }
}

impl RewardSegmentCircuit {
    pub fn new() -> Self { build_segment() }

    fn set_witness(&self, input: &RewardSegmentWitness) -> anyhow::Result<PartialWitness<F>> {
        let count = input.source.jobs.len();
        anyhow::ensure!((1..=REWARD_LEAF_CAPACITY).contains(&count), "reward segment job count out of range");
        anyhow::ensure!(input.source.nullifier.inner_siblings.len() == count, "reward job path count mismatch");
        anyhow::ensure!(input.source.jobs.iter().all(|job| job.source_checkpoint_id == input.source.source_checkpoint_id), "reward source mismatch");
        let mut witness = PartialWitness::new();
        witness.set_target(self.targets.active_len, F::from_canonical_usize(count))?;
        witness.set_target(self.targets.user_id, F::from_canonical_u32(input.user_id))?;
        witness.set_target(self.targets.anchor_checkpoint_id, F::from_canonical_u32(input.anchor_checkpoint_id))?;
        witness.set_hash_target(self.targets.checkpoint_tree_root, input.checkpoint_tree_root)?;
        witness.set_hash_target(self.targets.old_nullifier_root, input.old_nullifier_root)?;
        self.targets.source.membership.checkpoint_leaf.set_witness(&mut witness, &input.source.checkpoint_leaf)?;
        for (target, sibling) in self.targets.source.membership.path.siblings.iter().zip(input.source.checkpoint_siblings) {
            witness.set_hash_target(*target, sibling)?;
        }
        witness.set_target(self.targets.source.amount.low.0, F::from_canonical_u32(input.source.amount_limbs[0]))?;
        witness.set_target(self.targets.source.amount.high.0, F::from_canonical_u32(input.source.amount_limbs[1]))?;
        let nullifier = &self.targets.source.nullifier;
        witness.set_hash_target(nullifier.outer.old_value, input.source.nullifier.old_inner_root)?;
        for (&target, sibling) in nullifier.outer.siblings.iter().zip(input.source.nullifier.outer_siblings) { witness.set_hash_target(target, sibling)?; }
        for index in 0..REWARD_LEAF_CAPACITY {
            let job = &input.source.jobs[index.min(count - 1)];
            witness.set_target(self.targets.jobs[index].source, F::from_canonical_u32(input.source.source_checkpoint_id))?;
            witness.set_target(self.targets.jobs[index].height, F::from_canonical_u8(job.height))?;
            witness.set_target(self.targets.jobs[index].path_index, F::from_canonical_u32(job.path_index))?;
            self.targets.jobs[index].tag.set_witness(&mut witness, &job.tag)?;
            for (&target, sibling) in nullifier.inner[index].siblings.iter().zip(input.source.nullifier.inner_siblings[index.min(count - 1)]) {
                witness.set_hash_target(target, sibling)?;
            }
        }
        Ok(witness)
    }

    pub fn prove(&self, input: &RewardSegmentWitness) -> anyhow::Result<RewardSegmentProof> {
        self.circuit_data.prove(self.set_witness(input)?)
    }
}

fn merge_public_inputs(proof: &RewardMergeProof) -> anyhow::Result<&[F]> {
    anyhow::ensure!(proof.public_inputs.len() == REWARD_MERGE_STATEMENT_LEN + 4 + 4 * 16, "reward merge statement width mismatch");
    Ok(&proof.public_inputs)
}

impl RewardMergeCircuit {
    pub fn new(segment: &RewardSegmentCircuit) -> Self { build_merge(segment) }

    fn validate(&self, input: &RewardMergeWitness) -> anyhow::Result<()> {
        match input {
            RewardMergeWitness::Leaf { segment } => {
                anyhow::ensure!(segment.public_inputs.len() == REWARD_SEGMENT_STATEMENT_LEN, "reward segment statement width mismatch");
                plonky2::plonk::verifier_helper::verify_proof_borrowed(segment, &self.segment_verifier, &self.segment_common)?;
            }
            RewardMergeWitness::Pair { left, right } => {
                let (left_inputs, right_inputs) = (merge_public_inputs(left)?, merge_public_inputs(right)?);
                anyhow::ensure!(left_inputs[SEGMENT_USER] == right_inputs[SEGMENT_USER], "reward merge users differ");
                anyhow::ensure!(left_inputs[SEGMENT_ANCHOR..SEGMENT_OLD] == right_inputs[SEGMENT_ANCHOR..SEGMENT_OLD], "reward merge anchors differ");
                anyhow::ensure!(left_inputs[SEGMENT_NEW..SEGMENT_COUNT] == right_inputs[SEGMENT_OLD..SEGMENT_NEW], "reward merge continuity is broken");
                let count = left_inputs[SEGMENT_COUNT].to_canonical_u64() + right_inputs[SEGMENT_COUNT].to_canonical_u64();
                anyhow::ensure!(count <= u64::from(u32::MAX), "reward merge count overflow");
                let mut carry = 0u128;
                for index in 0..8 {
                    carry += u128::from(left_inputs[SEGMENT_AMOUNT + index].to_canonical_u64())
                        + u128::from(right_inputs[SEGMENT_AMOUNT + index].to_canonical_u64());
                    carry >>= 32;
                }
                anyhow::ensure!(carry == 0, "reward merge amount overflow");
                check_cyclic_proof_verifier_data(left, &self.circuit_data.verifier_only, &self.circuit_data.common)?;
                check_cyclic_proof_verifier_data(right, &self.circuit_data.verifier_only, &self.circuit_data.common)?;
            }
        }
        Ok(())
    }

    fn set_witness(&self, input: &RewardMergeWitness) -> anyhow::Result<PartialWitness<F>> {
        self.validate(input)?;
        let mut witness = PartialWitness::new();
        self.seed.set_witness(&mut witness)?;
        let (leaf, segment, left, right) = match input {
            RewardMergeWitness::Leaf { segment } => (true, segment, None, None),
            RewardMergeWitness::Pair { left, right } => (false, &self.dummy_segment_proof, Some(left), Some(right)),
        };
        witness.set_bool_target(self.targets.is_leaf, leaf)?;
        witness.set_bool_target(self.targets.is_pair, !leaf)?;
        witness.set_verifier_data_target(&self.targets.pinned_merge, &self.circuit_data.verifier_only)?;
        witness.set_proof_with_pis_target(&self.targets.segment_proof, segment)?;
        witness.set_proof_with_pis_target(&self.targets.inactive_segment_proof, &self.dummy_segment_proof)?;
        let identity = cyclic_base_proof(&self.circuit_data.common, &self.circuit_data.verifier_only, HashMap::new());
        witness.set_proof_with_pis_target(&self.targets.child_proofs[0], left.unwrap_or(&identity))?;
        witness.set_proof_with_pis_target(&self.targets.child_proofs[1], right.unwrap_or(&identity))?;
        let statement = if leaf { &segment.public_inputs } else { &left.unwrap().public_inputs };
        witness.set_target(self.targets.user_id, statement[SEGMENT_USER])?;
        witness.set_hash_target(self.targets.checkpoint_tree_root, hash_value(statement, SEGMENT_ANCHOR))?;
        witness.set_hash_target(self.targets.old_nullifier_root, hash_value(statement, SEGMENT_OLD))?;
        let new_root = if leaf { hash_value(statement, SEGMENT_NEW) } else { hash_value(&right.unwrap().public_inputs, SEGMENT_NEW) };
        witness.set_hash_target(self.targets.new_nullifier_root, new_root)?;
        if leaf {
            witness.set_target(self.targets.count, statement[SEGMENT_COUNT])?;
            for index in 0..8 { witness.set_target(self.targets.amount[index].0, statement[SEGMENT_AMOUNT + index])?; }
        } else {
            let right = &right.unwrap().public_inputs;
            let count = statement[SEGMENT_COUNT].to_canonical_u64() + right[SEGMENT_COUNT].to_canonical_u64();
            witness.set_target(self.targets.count, F::from_canonical_u64(count))?;
            let mut carry = 0u64;
            for index in 0..8 {
                let sum = statement[SEGMENT_AMOUNT + index].to_canonical_u64() + right[SEGMENT_AMOUNT + index].to_canonical_u64() + carry;
                witness.set_target(self.targets.amount[index].0, F::from_canonical_u64(sum & 0xffff_ffff))?;
                carry = sum >> 32;
            }
            anyhow::ensure!(carry == 0, "reward merge amount overflow");
        }
        Ok(witness)
    }

    pub fn prove(&self, input: &RewardMergeWitness) -> anyhow::Result<RewardMergeProof> {
        let proof = self.circuit_data.prove(self.set_witness(input)?)?;
        check_cyclic_proof_verifier_data(&proof, &self.circuit_data.verifier_only, &self.circuit_data.common)?;
        Ok(proof)
    }
}

fn bind_suffix(builder: &mut CircuitBuilder<F, D>, inputs: &[Target], verifier: &VerifierCircuitTarget) {
    let start = REWARD_MERGE_STATEMENT_LEN;
    assert_eq!(inputs.len() - start, 4 + 4 * 16);
    assert_eq!(verifier.constants_sigmas_cap.0.len(), 16);
    for index in 0..4 { builder.connect(inputs[start + index], verifier.circuit_digest.elements[index]); }
    for (index, cap) in verifier.constants_sigmas_cap.0.iter().enumerate() {
        for limb in 0..4 { builder.connect(inputs[start + 4 + 4 * index + limb], cap.elements[limb]); }
    }
}

fn build_root(merge: &RewardMergeCircuit) -> RewardRootCircuit {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let zero = builder.zero();
    let merge_proof = builder.add_virtual_proof_with_pis(&merge.circuit_data.common);
    let merge_verifier = builder.constant_verifier_data(&merge.circuit_data.verifier_only);
    builder.verify_proof::<C>(&merge_proof, &merge_verifier, &merge.circuit_data.common);
    bind_suffix(&mut builder, &merge_proof.public_inputs, &merge_verifier);
    let child = &merge_proof.public_inputs;
    let user_id = child[SEGMENT_USER];
    let checkpoint_tree_root = pi_hash(child, SEGMENT_ANCHOR);
    let old_nullifier_root = pi_hash(child, SEGMENT_OLD);
    let new_nullifier_root = pi_hash(child, SEGMENT_NEW);
    let count = child[SEGMENT_COUNT];
    builder.assert_non_zero(count);
    let amount = std::array::from_fn(|index| child[SEGMENT_AMOUNT + index]);
    let anchor_id = builder.add_virtual_target();
    builder.range_check(anchor_id, 32);
    let anchor_leaf = PsyCheckpointLeafGadget::create_virtual(&mut builder);
    let anchor = historical_merkle_proof(&mut builder, [anchor_id, zero], &anchor_leaf, [anchor_id, zero], checkpoint_tree_root);
    let global_roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(&mut builder);
    let global_hash = global_roots.to_hash::<PoseidonHash, F, D>(&mut builder);
    builder.connect_hashes(global_hash, anchor_leaf.global_chain_root);
    let user = PsyUserLeafGadget::create_virtual(&mut builder);
    builder.range_check(user.user_id, 32);
    builder.connect(user.user_id, user_id);
    let user_hash = user.to_hash::<PoseidonHash, F, D>(&mut builder);
    let user_path = MerkleProofGadget::add_virtual_to_with_options::<PoseidonHash, F, D>(
        &mut builder, GLOBAL_USER_TREE_HEIGHT as usize, OptionalMerkleProofGadget {
            root: Some(global_roots.user_tree_root), value: Some(user_hash), index: Some(user.user_id), siblings: None,
        },
    );
    let private_key = builder.add_virtual_hash();
    let identity = builder.constant_hash(PsyBasicZKSignatureCircuit::<C, D>::new().fingerprint.0);
    let public_key_param = get_zk_public_key_param::<C, D>(&mut builder, &private_key);
    let public_key = builder.hash_two_to_one::<PoseidonHash>(identity, public_key_param);
    builder.connect_hashes(user.public_key, public_key);
    let recipient: [Target; 8] = std::array::from_fn(|index| {
        let target = builder.add_virtual_target();
        if index < 5 { builder.range_check(target, 32); } else { builder.assert_zero(target); }
        target
    });
    let mut statement = vec![user_id];
    statement.extend(recipient);
    statement.extend(old_nullifier_root.elements);
    statement.extend(new_nullifier_root.elements);
    statement.push(count);
    statement.extend(amount);
    statement.extend(checkpoint_tree_root.elements);
    assert_eq!(statement.len(), REWARD_ROOT_STATEMENT_LEN);
    builder.register_public_inputs(&statement);
    let circuit_data = builder.build::<C>();
    assert_eq!(circuit_data.common.num_public_inputs, REWARD_ROOT_STATEMENT_LEN);
    let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
    RewardRootCircuit {
        targets: RewardRootTargets {
            user_id, recipient, old_nullifier_root, new_nullifier_root, count, amount, checkpoint_tree_root,
            anchor, global_roots, user, user_path, private_key, merge_proof,
        },
        circuit_data, fingerprint,
    }
}

impl RewardRootCircuit {
    pub fn new(merge: &RewardMergeCircuit) -> Self { build_root(merge) }

    pub fn prove(&self, input: &RewardRootWitness) -> anyhow::Result<RewardRootProof> {
        anyhow::ensure!(input.recipient[5..].iter().all(|limb| *limb == 0), "recipient exceeds 160 bits");
        anyhow::ensure!(input.merge_proof.public_inputs.len() == REWARD_MERGE_STATEMENT_LEN + 4 + 4 * 16, "reward merge statement width mismatch");
        anyhow::ensure!(input.merge_proof.public_inputs[SEGMENT_COUNT] != F::ZERO, "reward root count is zero");
        let mut witness = PartialWitness::new();
        for (&target, limb) in self.targets.recipient.iter().zip(input.recipient) { witness.set_target(target, F::from_canonical_u32(limb))?; }
        witness.set_target(self.targets.anchor.checkpoint_id[0], F::from_canonical_u32(input.anchor_checkpoint_id))?;
        self.targets.anchor.checkpoint_leaf.set_witness(&mut witness, &input.anchor_leaf)?;
        for (target, sibling) in self.targets.anchor.path.siblings.iter().zip(input.anchor_siblings) { witness.set_hash_target(*target, sibling)?; }
        self.targets.global_roots.set_witness(&mut witness, &input.global_roots)?;
        self.targets.user.set_witness(&mut witness, &input.user_leaf)?;
        for (target, sibling) in self.targets.user_path.siblings.iter().zip(input.user_siblings) { witness.set_hash_target(*target, sibling)?; }
        witness.set_hash_target(self.targets.private_key, input.private_key)?;
        witness.set_proof_with_pis_target(&self.targets.merge_proof, &input.merge_proof)?;
        self.circuit_data.prove(witness)
    }
}

impl QStandardCircuit<C, D> for RewardSegmentCircuit {
    fn get_fingerprint(&self) -> QHashOut<F> { self.fingerprint }
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> { &self.circuit_data.verifier_only }
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<F, D> { &self.circuit_data.common }
}

impl QStandardCircuit<C, D> for RewardMergeCircuit {
    fn get_fingerprint(&self) -> QHashOut<F> { self.fingerprint }
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> { &self.circuit_data.verifier_only }
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<F, D> { &self.circuit_data.common }
}

impl QStandardCircuit<C, D> for RewardRootCircuit {
    fn get_fingerprint(&self) -> QHashOut<F> { self.fingerprint }
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> { &self.circuit_data.verifier_only }
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<F, D> { &self.circuit_data.common }
}

#[cfg(test)]
pub(in crate::bridge::circuits) mod tests {
    use super::*;
    use psy_crypto::hash::traits::qhashable::QFieldHashable;
    use crate::bridge::gadgets::reward_nullifier::{INNER_EMPTY_ROOT, REWARD_NULLIFIER_OCCUPIED_LEAF};

    fn tagged(left: HashOut<F>, right: HashOut<F>, tag: HashOut<F>) -> HashOut<F> {
        PoseidonHash::two_to_one(PoseidonHash::two_to_one(left, right), tag)
    }

    pub(in crate::bridge::circuits) struct Fixture {
        user_id: u32,
        anchor_checkpoint_id: u32,
        anchor_leaf: PsyCheckpointLeaf<F>,
        checkpoint: PsyCheckpointLeaf<F>, pub(in crate::bridge::circuits) checkpoints: Leaves, pub(super) jobs: Vec<AuthenticatedJobWitness>,
        inner: BTreeMap<u32, Leaves>, outer: Leaves,
    }

    impl Fixture {
        fn new() -> Self { Self::for_user(7, 12) }

        pub(in crate::bridge::circuits) fn for_user(user_id: u32, anchor_checkpoint_id: u32) -> Self {
            // The imported nonzero-hash guard requires every preimage limb to be nonzero.
            let preimage = QHashOut::from_values(u64::from(user_id), 1, 2, 3);
            let tag = PoseidonHash::two_to_one(preimage.0, preimage.0);
            let mut levels = vec![(0..64).map(|index| tagged(QHashOut::from_values(index, 0, 0, 0).0, HashOut::ZERO, tag)).collect::<Vec<_>>()];
            for level in 0..6 {
                let parents = levels[level].chunks_exact(2).map(|pair| tagged(pair[0], pair[1], HashOut::ZERO)).collect();
                levels.push(parents);
            }
            let jobs = (0..16).map(|index| AuthenticatedJobWitness {
                source_checkpoint_id: 10, height: 6, path_index: index as u32,
                tag: RewardTagWitness {
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
            Self { user_id, anchor_checkpoint_id, anchor_leaf, checkpoint, checkpoints, jobs, inner: BTreeMap::new(), outer: Leaves::new() }
        }

        pub(in crate::bridge::circuits) fn node(&mut self, source: u32, indices: std::ops::Range<usize>) -> RewardSegmentWitness {
            let (outer_siblings, old_nullifier_root) = path::<32>(&self.outer, source as u64, *INNER_EMPTY_ROOT);
            let inner = self.inner.entry(source).or_default();
            let old_inner_root = path::<22>(inner, 0, HashOut::ZERO).1;
            let mut inner_siblings = Vec::new();
            let jobs = indices.map(|index| {
                let mut job = self.jobs[index.min(15)].clone();
                job.source_checkpoint_id = source;
                let coordinate = 63 + u64::from(job.path_index);
                inner_siblings.push(path::<22>(inner, coordinate, HashOut::ZERO).0);
                inner.insert(coordinate, REWARD_NULLIFIER_OCCUPIED_LEAF);
                job
            }).collect::<Vec<_>>();
            self.outer.insert(source as u64, path::<22>(inner, 0, HashOut::ZERO).1);
            let (checkpoint_siblings, checkpoint_tree_root) = path::<32>(&self.checkpoints, source as u64, HashOut::ZERO);
            RewardSegmentWitness {
                user_id: self.user_id, anchor_checkpoint_id: self.anchor_checkpoint_id, checkpoint_tree_root, old_nullifier_root,
                source: RewardSegmentSourceWitness {
                    source_checkpoint_id: source, checkpoint_leaf: self.checkpoint.clone(), checkpoint_siblings,
                    amount_limbs: [jobs.len() as u32 * 10, 0], jobs,
                    nullifier: RewardNullifierSourceWitness { old_inner_root, outer_siblings, inner_siblings },
                },
            }
        }
    }

    pub(super) fn reward_fixture() -> Fixture { Fixture::for_user(7, 12) }

    fn anchor_leaf(user_id: u32) -> PsyCheckpointLeaf<F> {
        let private_key = QHashOut::from_values(17, 23, 31, 47);
        let client_key = psy_client_common::data::qhashout::QHashOut(private_key.0);
        let param = psy_ups_circuit::signature::software_defined::get_sdc_public_key_param(&client_key);
        let identity = PsyBasicZKSignatureCircuit::<C, D>::new().fingerprint.0;
        let mut user = PsyUserLeaf::default();
        user.user_id = F::from_canonical_u32(user_id);
        user.public_key.0 = PoseidonHash::two_to_one(identity, param.0);
        let user_root = path::<{ GLOBAL_USER_TREE_HEIGHT as usize }>(&Leaves::from([(u64::from(user_id), user.qfhash::<PoseidonHash>().0)]), u64::from(user_id), HashOut::ZERO).1;
        let mut global_roots = PsyCheckpointGlobalStateRoots::default();
        global_roots.user_tree_root.0 = user_root;
        let mut anchor_leaf = PsyCheckpointLeaf::default();
        anchor_leaf.global_chain_root = global_roots.qfhash::<PoseidonHash>();
        anchor_leaf
    }

    pub(in crate::bridge::circuits) fn reward_root(root: &RewardRootCircuit, fixture: &Fixture, recipient: u64, merge_proof: RewardMergeProof) -> RewardRootProof {
        let private_key = QHashOut::from_values(17, 23, 31, 47);
        let client_key = psy_client_common::data::qhashout::QHashOut(private_key.0);
        let param = psy_ups_circuit::signature::software_defined::get_sdc_public_key_param(&client_key);
        let identity = PsyBasicZKSignatureCircuit::<C, D>::new().fingerprint.0;
        let mut user = PsyUserLeaf::default();
        user.user_id = F::from_canonical_u32(fixture.user_id);
        user.public_key.0 = PoseidonHash::two_to_one(identity, param.0);
        let user_hash = user.qfhash::<PoseidonHash>().0;
        let (user_siblings, user_root) = path::<{ GLOBAL_USER_TREE_HEIGHT as usize }>(&Leaves::from([(u64::from(fixture.user_id), user_hash)]), u64::from(fixture.user_id), HashOut::ZERO);
        let mut global_roots = PsyCheckpointGlobalStateRoots::default();
        global_roots.user_tree_root.0 = user_root;
        let anchor_siblings = path::<32>(&fixture.checkpoints, u64::from(fixture.anchor_checkpoint_id), HashOut::ZERO).0;
        let input = RewardRootWitness {
            recipient: [recipient as u32, 2, 3, 4, 5, 0, 0, 0], anchor_checkpoint_id: fixture.anchor_checkpoint_id, anchor_leaf: fixture.anchor_leaf.clone(),
            anchor_siblings, global_roots, user_leaf: user, user_siblings, private_key: private_key.0, merge_proof,
        };
        root.prove(&input).expect("reward root proof")
    }

    fn lift(merge: &RewardMergeCircuit, proof: RewardSegmentProof) -> RewardMergeProof {
        merge.prove(&RewardMergeWitness::Leaf { segment: proof }).unwrap()
    }

    fn pair(merge: &RewardMergeCircuit, left: RewardMergeProof, right: RewardMergeProof) -> RewardMergeProof {
        merge.prove(&RewardMergeWitness::Pair { left, right }).unwrap()
    }

    fn business(proof: &RewardMergeProof) -> [F; REWARD_MERGE_STATEMENT_LEN] {
        proof.public_inputs[..REWARD_MERGE_STATEMENT_LEN].try_into().unwrap()
    }

    #[test]
    fn leaf_merge_verifies_real_segment() {
        let segment = RewardSegmentCircuit::new();
        let merge = RewardMergeCircuit::new(&segment);
        let mut fixture = Fixture::new();
        let proof = segment.prove(&fixture.node(10, 0..1)).unwrap();
        let statement = proof.public_inputs.clone();
        segment.circuit_data.verify(proof.clone()).unwrap();
        let proof = lift(&merge, proof);
        assert_eq!(&proof.public_inputs[..REWARD_MERGE_STATEMENT_LEN], statement.as_slice());
        check_cyclic_proof_verifier_data(&proof, &merge.circuit_data.verifier_only, &merge.circuit_data.common).unwrap();
        merge.circuit_data.verify(proof).unwrap();
    }

    #[test]
    fn singleton_odd_even_and_parenthesizations_share_business_fields() {
        let segment = RewardSegmentCircuit::new();
        let merge = RewardMergeCircuit::new(&segment);
        let mut fixture = Fixture::new();
        let initial_root = path::<32>(&fixture.outer, 10, *INNER_EMPTY_ROOT).1;
        let first = lift(&merge, segment.prove(&fixture.node(10, 0..1)).unwrap());
        assert_eq!(first.public_inputs[SEGMENT_COUNT], F::ONE);
        let second = lift(&merge, segment.prove(&fixture.node(10, 1..3)).unwrap());
        let third = lift(&merge, segment.prove(&fixture.node(11, 0..16)).unwrap());
        let left_heavy = pair(&merge, pair(&merge, first.clone(), second.clone()), third.clone());
        let right_heavy = pair(&merge, first, pair(&merge, second, third));
        assert_eq!(business(&left_heavy), business(&right_heavy));
        assert_eq!(left_heavy.public_inputs[SEGMENT_COUNT], F::from_canonical_u32(19));
        assert_eq!(&left_heavy.public_inputs[SEGMENT_OLD..SEGMENT_NEW], &initial_root.elements);
        merge.circuit_data.verify(left_heavy).unwrap();
        merge.circuit_data.verify(right_heavy).unwrap();
    }

    #[test]
    fn nonmonotone_omitted_jobs_and_decreasing_seam_remain_payable() {
        let segment = RewardSegmentCircuit::new();
        let merge = RewardMergeCircuit::new(&segment);
        let mut fixture = Fixture::new();
        let high = lift(&merge, segment.prove(&fixture.node(10, 12..16)).unwrap());
        let low = lift(&merge, segment.prove(&fixture.node(10, 0..1)).unwrap());
        let seam = pair(&merge, high, low);
        assert_eq!(seam.public_inputs[SEGMENT_COUNT], F::from_canonical_u32(5));
        merge.circuit_data.verify(seam).unwrap();
        let omitted = segment.prove(&fixture.node(10, 2..4)).unwrap();
        assert_eq!(omitted.public_inputs[SEGMENT_COUNT], F::TWO);
        segment.circuit_data.verify(omitted).unwrap();
    }

    #[test]
    fn one_source_split_and_multiple_sources_thread_roots() {
        let segment = RewardSegmentCircuit::new();
        let merge = RewardMergeCircuit::new(&segment);
        let mut fixture = Fixture::new();
        let first = fixture.node(10, 0..8);
        let first_old = first.old_nullifier_root;
        let first_proof = lift(&merge, segment.prove(&first).unwrap());
        let second = fixture.node(10, 8..16);
        assert_eq!(second.old_nullifier_root.elements, first_proof.public_inputs[SEGMENT_NEW..SEGMENT_COUNT]);
        let same_source = pair(&merge, first_proof, lift(&merge, segment.prove(&second).unwrap()));
        let other = lift(&merge, segment.prove(&fixture.node(11, 0..2)).unwrap());
        let combined = pair(&merge, same_source, other);
        assert_eq!(&combined.public_inputs[SEGMENT_OLD..SEGMENT_NEW], &first_old.elements);
        assert_eq!(combined.public_inputs[SEGMENT_COUNT], F::from_canonical_u32(18));
        merge.circuit_data.verify(combined).unwrap();
    }

    #[test]
    fn rejects_rate_membership_owner_absence_and_accumulator_tampering() {
        let segment = RewardSegmentCircuit::new();
        let mut fixture = Fixture::new();
        let input = fixture.node(10, 0..2);
        for mutation in 0..7 {
            let mut bad = input.clone();
            match mutation {
                0 => bad.source.amount_limbs[0] += 1,
                1 => bad.source.checkpoint_leaf.stats.guta_fees_collected += F::ONE,
                2 => bad.source.jobs[0].tag.tag_preimage.0.elements[0] = F::from_canonical_u32(8),
                3 => bad.source.nullifier.old_inner_root.elements[0] += F::ONE,
                4 => bad.source.nullifier.outer_siblings[0].elements[0] += F::ONE,
                5 => bad.source.nullifier.inner_siblings[0][0].elements[0] += F::ONE,
                _ => bad.old_nullifier_root.elements[0] += F::ONE,
            }
            assert!(segment.prove(&bad).is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn independent_claims_allow_lower_labels_but_reject_replay() {
        let segment = RewardSegmentCircuit::new();
        let mut fixture = Fixture::new();
        let proof = segment.prove(&fixture.node(10, 12..16)).unwrap();
        assert_eq!(proof.public_inputs[SEGMENT_COUNT], F::from_canonical_u32(4));
        let new_root = hash_value(&proof.public_inputs, SEGMENT_NEW);
        segment.circuit_data.verify(proof).unwrap();
        let proof = segment.prove(&fixture.node(10, 0..1)).unwrap();
        assert_eq!(proof.public_inputs[SEGMENT_COUNT], F::ONE);
        assert_eq!(hash_value(&proof.public_inputs, SEGMENT_OLD), new_root);
        segment.circuit_data.verify(proof).unwrap();
        assert!(segment.prove(&fixture.node(10, 0..1)).is_err());
    }

    #[test]
    fn rejects_counted_gu_boundary_and_source_mismatch() {
        let segment = RewardSegmentCircuit::new();
        let mut fixture = Fixture::new();
        let mut input = fixture.node(10, 0..1);
        input.source.jobs[0].path_index = 16;
        assert!(segment.prove(&input).is_err());
        input.source.jobs[0].source_checkpoint_id += 1;
        assert!(segment.set_witness(&input).is_err());
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
    fn root_authenticates_user_anchor_private_key_and_merge_suffix() {
        let segment = RewardSegmentCircuit::new();
        let merge = RewardMergeCircuit::new(&segment);
        let root = RewardRootCircuit::new(&merge);
        let mut fixture = Fixture::new();
        let private_key = QHashOut::from_values(17, 23, 31, 47);
        let client_key = psy_client_common::data::qhashout::QHashOut(private_key.0);
        let param = psy_ups_circuit::signature::software_defined::get_sdc_public_key_param(&client_key);
        let identity = PsyBasicZKSignatureCircuit::<C, D>::new().fingerprint.0;
        let mut user = PsyUserLeaf::default();
        user.user_id = F::from_canonical_u32(7);
        user.public_key.0 = PoseidonHash::two_to_one(identity, param.0);
        let user_hash = user.qfhash::<PoseidonHash>().0;
        let (user_siblings, user_root) = path::<{ GLOBAL_USER_TREE_HEIGHT as usize }>(&Leaves::from([(7, user_hash)]), 7, HashOut::ZERO);
        let mut global_roots = PsyCheckpointGlobalStateRoots::default();
        global_roots.user_tree_root.0 = user_root;
        let mut anchor_leaf = PsyCheckpointLeaf::default();
        anchor_leaf.global_chain_root = global_roots.qfhash::<PoseidonHash>();
        fixture.checkpoints.insert(11, anchor_leaf.qfhash::<PoseidonHash>().0);
        let node = fixture.node(10, 0..1);
        let merge_proof = lift(&merge, segment.prove(&node).unwrap());
        let anchor_siblings = path::<32>(&fixture.checkpoints, 11, HashOut::ZERO).0;
        let input = RewardRootWitness {
            recipient: [1, 2, 3, 4, 5, 0, 0, 0], anchor_checkpoint_id: 11, anchor_leaf,
            anchor_siblings, global_roots, user_leaf: user, user_siblings, private_key: private_key.0, merge_proof,
        };
        let proof = root.prove(&input).unwrap();
        assert_eq!(proof.public_inputs.len(), REWARD_ROOT_STATEMENT_LEN);
        assert_eq!(&proof.public_inputs[9..13], &node.old_nullifier_root.elements);
        root.circuit_data.verify(proof).unwrap();
        for mutation in 0..6 {
            let mut bad = input.clone();
            match mutation {
                0 => bad.private_key.elements[0] += F::ONE,
                1 => bad.user_leaf.public_key.0.elements[0] += F::ONE,
                2 => bad.anchor_leaf.global_chain_root.0.elements[0] += F::ONE,
                3 => bad.merge_proof.public_inputs[SEGMENT_NEW] += F::ONE,
                4 => bad.merge_proof.public_inputs[REWARD_MERGE_STATEMENT_LEN] += F::ONE,
                _ => bad.user_siblings[0].elements[0] += F::ONE,
            }
            assert!(root.prove(&bad).is_err(), "root mutation {mutation}");
        }
    }

    #[test]
    fn rejects_duplicate_coordinates_repeated_proof_and_mismatched_user_anchor() {
        let segment = RewardSegmentCircuit::new();
        let merge = RewardMergeCircuit::new(&segment);
        let root = RewardRootCircuit::new(&merge);
        let mut duplicate_fixture = Fixture::new();
        let mut duplicate = duplicate_fixture.node(10, 0..2);
        duplicate.source.jobs[1].path_index = duplicate.source.jobs[0].path_index;
        assert!(segment.prove(&duplicate).is_err(), "duplicate coordinates were accepted");
        let mut repeated_fixture = Fixture::new();
        let repeated = lift(&merge, segment.prove(&repeated_fixture.node(10, 0..1)).unwrap());
        assert!(merge.prove(&RewardMergeWitness::Pair { left: repeated.clone(), right: repeated }).is_err(), "same proof twice was accepted");
        let mut first_fixture = Fixture::new();
        let first = lift(&merge, segment.prove(&first_fixture.node(10, 0..1)).unwrap());
        let mut other_anchor = Fixture::for_user(7, 13);
        let second = lift(&merge, segment.prove(&other_anchor.node(10, 1..2)).unwrap());
        assert!(merge.prove(&RewardMergeWitness::Pair { left: first.clone(), right: second }).is_err(), "mismatched anchor was accepted");
        let private_key = QHashOut::from_values(17, 23, 31, 47);
        let client_key = psy_client_common::data::qhashout::QHashOut(private_key.0);
        let param = psy_ups_circuit::signature::software_defined::get_sdc_public_key_param(&client_key);
        let identity = PsyBasicZKSignatureCircuit::<C, D>::new().fingerprint.0;
        let mut user = PsyUserLeaf::default();
        user.user_id = F::from_canonical_u32(7);
        user.public_key.0 = PoseidonHash::two_to_one(identity, param.0);
        let user_hash = user.qfhash::<PoseidonHash>().0;
        let (user_siblings, user_root) = path::<{ GLOBAL_USER_TREE_HEIGHT as usize }>(&Leaves::from([(7, user_hash)]), 7, HashOut::ZERO);
        let mut global_roots = PsyCheckpointGlobalStateRoots::default();
        global_roots.user_tree_root.0 = user_root;
        let mut anchor_leaf = PsyCheckpointLeaf::default();
        anchor_leaf.global_chain_root = global_roots.qfhash::<PoseidonHash>();
        let mut anchor_fixture = Fixture::for_user(8, 12);
        anchor_fixture.checkpoints.insert(11, anchor_leaf.qfhash::<PoseidonHash>().0);
        let other_user = anchor_fixture.node(10, 2..3);
        let merge_proof = lift(&merge, segment.prove(&other_user).unwrap());
        let anchor_siblings = path::<32>(&anchor_fixture.checkpoints, 11, HashOut::ZERO).0;
        let input = RewardRootWitness {
            recipient: [1, 2, 3, 4, 5, 0, 0, 0], anchor_checkpoint_id: 11, anchor_leaf,
            anchor_siblings, global_roots, user_leaf: user, user_siblings, private_key: private_key.0, merge_proof,
        };
        assert!(root.prove(&input).is_err(), "mismatched merge user was accepted");
    }

    #[test]
    fn authenticated_zero_denominator_and_excess_count_are_rejected() {
        let segment = RewardSegmentCircuit::new();
        for completed in [0, 1] {
            let mut fixture = Fixture::new();
            fixture.checkpoint.stats.pm_jobs_completed.gutas_completed = F::from_canonical_u32(completed);
            fixture.checkpoints.insert(10, fixture.checkpoint.qfhash::<PoseidonHash>().0);
            let input = fixture.node(10, 0..2);
            assert!(segment.prove(&input).is_err());
        }
    }

    #[test]
    fn exact_rate_and_nullifier_transition_boundaries() {
        let segment = RewardSegmentCircuit::new();
        let merge = RewardMergeCircuit::new(&segment);
        let mut fixture = Fixture::new();
        fixture.checkpoint.stats.pm_jobs_completed.gutas_completed = F::ONE;
        fixture.checkpoint.stats.guta_fees_collected = F::from_canonical_u64(0xffff_fffe_ffff_ffff);
        fixture.checkpoints.insert(10, fixture.checkpoint.qfhash::<PoseidonHash>().0);
        let mut exact = fixture.node(10, 0..1);
        exact.source.amount_limbs = [u32::MAX, u32::MAX - 1];
        let proof = segment.prove(&exact).unwrap();
        assert_eq!(proof.public_inputs[SEGMENT_AMOUNT], F::from_canonical_u32(u32::MAX));
        assert_eq!(proof.public_inputs[SEGMENT_AMOUNT + 1], F::from_canonical_u32(u32::MAX - 1));
        segment.circuit_data.verify(proof).unwrap();
        exact.source.amount_limbs = [0, u32::MAX];
        assert!(segment.prove(&exact).is_err(), "one token above the authenticated rate was accepted");

        let mut replay = Fixture::new();
        let first = replay.node(10, 0..1);
        let first_proof = lift(&merge, segment.prove(&first).unwrap());
        let mut continued = Fixture::new();
        let mut repeated = continued.node(10, 1..2);
        repeated.source.nullifier.old_inner_root = first.source.nullifier.old_inner_root;
        repeated.old_nullifier_root = first.old_nullifier_root;
        let second = lift(&merge, segment.prove(&repeated).unwrap());
        assert!(merge.prove(&RewardMergeWitness::Pair { left: first_proof, right: second }).is_err(), "broken continuity was accepted");
    }

    #[test]
    fn rejects_unpinned_segment_and_merge_verifiers() {
        let segment = RewardSegmentCircuit::new();
        let merge = RewardMergeCircuit::new(&segment);
        let mut fixture = Fixture::new();
        let proof = segment.prove(&fixture.node(10, 0..1)).unwrap();
        let mut witness = merge.set_witness(&RewardMergeWitness::Leaf { segment: proof }).unwrap();
        let mut replacement = PartialWitness::new();
        replacement.set_verifier_data_target(&merge.targets.pinned_merge, &segment.circuit_data.verifier_only).unwrap();
        for (target, value) in replacement.target_values { witness.target_values.insert(target, value); }
        assert!(merge.circuit_data.prove(witness).is_err(), "unpinned merge verifier was accepted");
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
    fn fixed_statement_and_tree_dimensions() {
        assert_eq!(REWARD_SEGMENT_STATEMENT_LEN, 22);
        assert_eq!(REWARD_MERGE_STATEMENT_LEN, 22);
        assert_eq!(REWARD_MERGE_STATEMENT_LEN + 4 + 4 * 16, 90);
        assert_eq!(REWARD_ROOT_STATEMENT_LEN, 30);
        assert_eq!(REWARD_LEAF_CAPACITY, 16);
        assert_eq!(REWARD_NULLIFIER_INNER_HEIGHT, 22);
        assert_eq!(REWARD_NULLIFIER_OUTER_HEIGHT, 32);
        assert_eq!(path::<22>(&Leaves::new(), 0, REWARD_NULLIFIER_EMPTY_LEAF).1, *crate::bridge::gadgets::reward_nullifier::INNER_EMPTY_ROOT);
    }

    #[test]
    fn host_rejects_empty_segment() {
        let segment = RewardSegmentCircuit::new();
        let empty = RewardSegmentWitness {
            user_id: 7, anchor_checkpoint_id: 10, checkpoint_tree_root: HashOut::ZERO, old_nullifier_root: HashOut::ZERO,
            source: RewardSegmentSourceWitness {
                source_checkpoint_id: 10, checkpoint_leaf: PsyCheckpointLeaf::default(), checkpoint_siblings: [HashOut::ZERO; 32],
                amount_limbs: [0, 0], jobs: Vec::new(),
                nullifier: RewardNullifierSourceWitness { old_inner_root: HashOut::ZERO, outer_siblings: [HashOut::ZERO; 32], inner_siblings: Vec::new() },
            },
        };
        assert!(segment.prove(&empty).is_err());
    }
}
