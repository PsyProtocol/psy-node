use parth_core::crypto::hash::traits::MerkleZeroHasher;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::{Field, Field64, PrimeField64}},
    hash::{hash_types::{HashOut, HashOutTarget}, poseidon::PoseidonHash},
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData}, config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}},
    recursion::dummy_circuit::{dummy_circuit, dummy_proof},
};
use psy_client_data::bridge_aggregate::{Bytes32, CircuitSetRegistration, Hash4, InclusionAggregateHeader, NetworkConfig, SourceCheckpointRewardLeaf, SourceCheckpointRewardOpening, WithdrawalLeaf, BRIDGE_USER_ID, CLAIM_TREE_MAX_CAPACITY, INCLUSION_AGGREGATE_CAPACITIES, REWARD_PUBLICATION_FAMILY, SOURCE_CHECKPOINT_REWARD_LEAF_BYTES, SOURCE_CHECKPOINT_REWARD_OPENING_HEADER_BYTES, REWARD_SESSION_PROOF_FIELD_COUNT, WITHDRAWAL_PUBLICATION_FAMILY};
use psy_client_data::qdata::checkpoint::PsyCheckpointLeaf;
use psy_common_circuit::{serialization::PsyGateSerializer, traits::{CreatableTarget, ToTargets}};
use psy_network_circuit::gadgets::qdata::checkpoint::PsyCheckpointLeafGadget;
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers};
use psy_plonky2_basic_helpers::u32::gadgets::arithmetic_u32::U32Target;
use psy_plonky2_common_circuits::{bridge::{aggregate_commitment::{self as hash, keccak_stream_absorb, keccak_stream_absorb_values, keccak_stream_finalize, keccak_stream_finalize_values, Bytes32Target, Domain, KeccakStreamTargets, KeccakStreamValues, AggregateLeafTarget, WithdrawalLeafTarget}, aggregate_config::NetworkConfigTarget}, hash::keccak::keccak256_bytes_targets};
use super::deposit_aggregate::less_words;
use super::historical_merkle_proof::{historical_merkle_proof, HistoricalMerkleProofTarget};
use super::reward_session::{reward_ledger_window_hash, reward_session_seed, reward_session_summary, summary_path_root, RewardLedgerStateTargets, RewardLedgerStateValues, RewardLedgerWindowTargets};
use crate::proof_minifier::pm_core::get_circuit_fingerprint_generic_q;
use parth_core::crypto::hash::traits::ToU64x4;
use tiny_keccak::Hasher as _;

type F = GoldilocksField;
/// Withdrawal and reward publication width.
pub const AGGREGATE_PI_LEN: usize = 28;
const WITHDRAWAL_ROOT_LEAF: u64 = 0x57524f4f544c;
const WITHDRAWAL_ROOT_EMPTY: u64 = 0x57524f4f5445;
const WITHDRAWAL_ROOT_NODE: u64 = 0x57524f4f544e;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AggregateFamily { Withdrawal = 2, Reward = 3 }

/// Internal reward hierarchy statement width.
pub const REWARD_AGGREGATE_NODE_PI_LEN: usize = 131;
/// Slots joined by one reward chunk. A power of two, and a divisor of the publication capacity.
pub const REWARD_CHUNK_SLOTS: usize = 4;
const REWARD_PUBLICATION_CAPACITY: usize = 1024;
/// Chunk descriptor plus one descriptor per combine level: `1 + log2(C / S)`.
pub const REWARD_HIERARCHY_LEVELS: usize = 9;
/// Bounded Keccak appends that absorb one reward chunk: `ceil(S * leaf bytes / 136)`.
pub const REWARD_CHUNK_ABSORB_CALLS: usize =
    (REWARD_CHUNK_SLOTS * SOURCE_CHECKPOINT_REWARD_LEAF_BYTES).div_ceil(136);
const REWARD_AGGREGATE_NODE_FAMILY: u8 = 13;
const REWARD_AGGREGATE_NODE_VARIANT: u8 = 3;

pub struct RewardInclusionAggregateCircuit {
    pub circuit_data: CircuitData<F, PoseidonGoldilocksConfig, 2>,
    session: VerifierCircuitData<F, PoseidonGoldilocksConfig, 2>,
    nodes: [VerifierCircuitData<F, PoseidonGoldilocksConfig, 2>; REWARD_HIERARCHY_LEVELS],
    source_chain_count: usize,
    registrations: [CircuitSetRegistration; REWARD_HIERARCHY_LEVELS],
    config: NetworkConfigTarget,
    config_hash: Bytes32Target,
    window_id: Bytes32Target,
    economic_domain: [Target; 32],
    start_root: HashOutTarget,
    end_id: Target,
    end_root: HashOutTarget,
    old_ledger_state_root: HashOutTarget,
    aggregate_capacity: Target,
    total_count: Target,
    segment_count: Target,
    segment_index: Target,
    first_ordinal: Target,
    count: Target,
    opening_digest: Bytes32Target,
    claim_tree_root: Bytes32Target,
    root_proof: ProofWithPublicInputsTarget<2>,
    final_proof: ProofWithPublicInputsTarget<2>,
    final_state: RewardLedgerStateTargets,
}

pub struct WithdrawalInclusionAggregateCircuit<C: GenericConfig<D, F = F>, const D: usize, const CAPACITY: usize>
where F: Extendable<D> {
    pub circuit_data: CircuitData<F, C, D>,
    config: NetworkConfigTarget,
    config_hash: Bytes32Target,
    window_id: Bytes32Target,
    end_id: [Target; 2],
    end_root: [Target; 4],
    aggregate_capacity: Target,
    total_count: Target,
    segment_count: Target,
    segment_index: Target,
    first_ordinal: Target,
    count: Target,
    withdrawal_roots: Vec<[Target; 4]>,
    opening_digest: Bytes32Target,
    claim_tree_root: Bytes32Target,
    leaf_words: Vec<Vec<Target>>,
    proofs: Vec<ProofWithPublicInputsTarget<D>>,
    paths: Vec<WithdrawalRootTarget>,
    dummy: CircuitData<F, C, D>,
}

#[derive(Clone, Debug)]
pub struct AggregateWindow {
    pub config_hash: Bytes32,
    pub window_id: Bytes32,
    pub end_id: u64,
    pub end_root: Hash4,
}

#[derive(Clone, Debug)]
pub struct WithdrawalRootPath {
    pub ordinal: u8,
    pub siblings: [Hash4; 8],
}

pub struct WithdrawalAggregateLeaf<'a, C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    pub leaf: &'a WithdrawalLeaf,
    pub proof: &'a ProofWithPublicInputs<F, C, D>,
    pub path: &'a WithdrawalRootPath,
}

pub struct RewardLedgerFinalProof<'a> {
    pub proof: &'a ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>,
    pub state: &'a RewardLedgerStateValues,
}

pub struct SourceCheckpointRewardAggregateLeaf<'a> {
    pub leaf: &'a SourceCheckpointRewardLeaf,
    pub proof: &'a ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>,
    pub state: &'a RewardLedgerStateValues,
    pub source_checkpoint_id: u32,
    pub source_leaf: &'a PsyCheckpointLeaf<F>,
    pub source_siblings: &'a [[u64; 4]; 32],
    pub session_root: [u64; 4],
    pub summary_siblings: &'a [[u64; 4]; 32],
}

struct RewardPayoutSlot {
    proof: ProofWithPublicInputsTarget<2>,
    state: RewardLedgerStateTargets,
    source_checkpoint_id: Target,
    source: HistoricalMerkleProofTarget,
    session_root: HashOutTarget,
    summary_siblings: [HashOutTarget; 32],
    leaf_words: [Target; 48],
    commit: Bytes32Target,
}




fn root_node<const D: usize>(builder: &mut CircuitBuilder<F, D>, level: usize, left: HashOutTarget, right: HashOutTarget) -> HashOutTarget
where F: Extendable<D> {
    let mut inputs = vec![builder.constant(F::from_canonical_u64(WITHDRAWAL_ROOT_NODE)), builder.constant(F::from_canonical_usize(level))];
    inputs.extend(left.elements);
    inputs.extend(right.elements);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs)
}

fn withdrawal_root_tree<const D: usize>(builder: &mut CircuitBuilder<F, D>, chains: &[(Target, [Target; 4])]) -> HashOutTarget
where F: Extendable<D> {
    assert!((1..=8).contains(&chains.len()));
    let mut nodes = (0..256).map(|ordinal| {
        let ordinal_target = builder.constant(F::from_canonical_usize(ordinal));
        let inputs = if ordinal < chains.len() {
            let mut inputs = vec![builder.constant(F::from_canonical_u64(WITHDRAWAL_ROOT_LEAF)), ordinal_target, chains[ordinal].0];
            inputs.extend(chains[ordinal].1);
            inputs
        } else { vec![builder.constant(F::from_canonical_u64(WITHDRAWAL_ROOT_EMPTY)), ordinal_target] };
        builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs)
    }).collect::<Vec<_>>();
    for level in 1..=8 {
        nodes = nodes.chunks_exact(2).map(|pair| root_node(builder, level, pair[0], pair[1])).collect();
    }
    nodes[0]
}

struct WithdrawalRootTarget {
    ordinal: Target,
    siblings: [HashOutTarget; 8],
}

impl WithdrawalRootTarget {
    fn build<const D: usize>(builder: &mut CircuitBuilder<F, D>, active: BoolTarget, chain_count: usize,
        chain_index: Target, withdrawal_root: [Target; 4], tree_root: HashOutTarget) -> Self
    where F: Extendable<D> {
        let ordinal = builder.add_virtual_target();
        let bits = builder.split_le(ordinal, 8);
        let count = builder.constant(F::from_canonical_usize(chain_count));
        let in_range = builder.is_less_than(9, ordinal, count);
        let one = builder.one();
        builder.connect_if_true(active, in_range.target, one);
        let inactive = builder.not(active);
        let zero = builder.zero();
        builder.connect_if_true(inactive, ordinal, zero);
        let mut inputs = vec![builder.constant(F::from_canonical_u64(WITHDRAWAL_ROOT_LEAF)), ordinal, chain_index];
        inputs.extend(withdrawal_root);
        let mut root = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
        let siblings: [HashOutTarget; 8] = std::array::from_fn(|_| builder.add_virtual_hash());
        for (level, sibling) in siblings.iter().enumerate() {
            for target in sibling.elements { builder.connect_if_true(inactive, target, zero); }
            let left = HashOutTarget { elements: std::array::from_fn(|j| builder.select(bits[level], sibling.elements[j], root.elements[j])) };
            let right = HashOutTarget { elements: std::array::from_fn(|j| builder.select(bits[level], root.elements[j], sibling.elements[j])) };
            root = root_node(builder, level + 1, left, right);
        }
        for i in 0..4 { builder.connect_if_true(active, root.elements[i], tree_root.elements[i]); }
        Self { ordinal, siblings }
    }

    fn set_witness(&self, witness: &mut PartialWitness<F>, path: Option<&WithdrawalRootPath>) -> anyhow::Result<()> {
        let empty = WithdrawalRootPath { ordinal: 0, siblings: [[0; 4]; 8] };
        let path = path.unwrap_or(&empty);
        witness.set_target(self.ordinal, F::from_canonical_u8(path.ordinal))?;
        for (target, sibling) in self.siblings.iter().zip(path.siblings) { set_hash4(witness, target.elements, sibling)?; }
        Ok(())
    }
}

pub fn withdrawal_root_paths(config: &NetworkConfig, roots: &[Hash4]) -> anyhow::Result<Vec<WithdrawalRootPath>> {
    config.validate()?;
    anyhow::ensure!(roots.len() == config.chains.len(), "withdrawal root count mismatch");
    let mut nodes = (0..256).map(|ordinal| {
        let mut inputs = if ordinal < roots.len() {
            vec![F::from_canonical_u64(WITHDRAWAL_ROOT_LEAF), F::from_canonical_usize(ordinal), F::from_canonical_u8(config.chains[ordinal].chain_index)]
        } else { vec![F::from_canonical_u64(WITHDRAWAL_ROOT_EMPTY), F::from_canonical_usize(ordinal)] };
        if ordinal < roots.len() {
            for value in roots[ordinal] {
                anyhow::ensure!(value < F::ORDER, "noncanonical withdrawal root");
                inputs.push(F::from_canonical_u64(value));
            }
        }
        Ok(PoseidonHash::hash_no_pad(&inputs))
    }).collect::<anyhow::Result<Vec<_>>>()?;
    let mut paths = (0..roots.len()).map(|ordinal| WithdrawalRootPath { ordinal: ordinal as u8, siblings: [[0; 4]; 8] }).collect::<Vec<_>>();
    for level in 0..8 {
        for (ordinal, path) in paths.iter_mut().enumerate() {
            path.siblings[level] = nodes[(ordinal >> level) ^ 1].elements.map(|value| value.to_canonical_u64());
        }
        nodes = nodes.chunks_exact(2).map(|pair| {
            let mut inputs = vec![F::from_canonical_u64(WITHDRAWAL_ROOT_NODE), F::from_canonical_usize(level + 1)];
            inputs.extend(pair[0].elements);
            inputs.extend(pair[1].elements);
            PoseidonHash::hash_no_pad(&inputs)
        }).collect();
    }
    Ok(paths)
}
fn leaf_target<const D: usize>(builder: &mut CircuitBuilder<F, D>) -> WithdrawalLeafTarget
where F: Extendable<D> {
    WithdrawalLeafTarget { chain_index: builder.add_virtual_target(), sender_user_id: builder.add_virtual_target(), recipient: builder.add_virtual_target_arr(), token: builder.add_virtual_target_arr(), amount: builder.add_virtual_target_arr(), nonce: builder.add_virtual_target_arr() }
}

fn leaf_key(leaf: WithdrawalLeafTarget) -> Vec<Target> {
    let mut key = vec![leaf.chain_index];
    key.extend(leaf.nonce);
    key
}
struct AggregateSlot<const D: usize> {
    leaf: AggregateLeafTarget,
    words: Vec<Target>,
    commit: Bytes32Target,
    proof: ProofWithPublicInputsTarget<D>,
    path: WithdrawalRootTarget,
}

fn constrain_aggregate_slot<C: GenericConfig<D, F = F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, index: usize, count: Target, zero: Target, one: Target,
    previous: Option<WithdrawalLeafTarget>, child: &CircuitData<F, C, D>, real_vk: &VerifierCircuitTarget,
    dummy_vk: &VerifierCircuitTarget, config_hash: Bytes32Target, end_id: [Target; 2], end_root: [Target; 4],
    chain_count: usize, tree_root: HashOutTarget, count_bits: usize,
) -> AggregateSlot<D>
where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    let slot = builder.constant(F::from_canonical_usize(index));
    let active = builder.is_less_than(count_bits, slot, count);
    let inactive = builder.not(active);
    let withdrawal = leaf_target(builder);
    let leaf = AggregateLeafTarget::Withdrawal(withdrawal);
    let words = leaf.encode(builder);
    for &word in &words { builder.connect_if_true(inactive, word, zero); }
    if let Some(previous) = previous {
        let increasing = less_words(builder, &leaf_key(previous), &leaf_key(withdrawal));
        builder.connect_if_true(active, increasing.target, one);
    }
    let proof = builder.add_virtual_proof_with_pis(&child.common);
    builder.conditionally_verify_proof::<C>(active, &proof, real_vk, &proof, dummy_vk, &child.common);
    let pi = &proof.public_inputs;
    for &word in pi { builder.connect_if_true(inactive, word, zero); }
    for (target, value) in pi[..4].iter().zip([1u8, AggregateFamily::Withdrawal as u8, 0, 0]) {
        let expected = builder.constant(F::from_canonical_u8(value));
        builder.connect_if_true(active, *target, expected);
    }
    for (left, right) in pi[4..18].iter().zip(config_hash.iter().chain(&end_id).chain(&end_root)) { builder.connect_if_true(active, *left, *right); }
    let commit = leaf.leaf_commit(builder);
    for j in 0..8 { builder.connect_if_true(active, pi[24 + j], commit[j]); }
    let bridge_user = builder.constant(F::from_canonical_u32(BRIDGE_USER_ID));
    builder.connect_if_true(active, pi[18], bridge_user);
    builder.connect_if_true(active, pi[19], withdrawal.chain_index);
    let path = WithdrawalRootTarget::build(builder, active, chain_count, withdrawal.chain_index, pi[20..24].try_into().unwrap(), tree_root);
    let commit = commit.map(|word| builder.select(active, word, zero));
    AggregateSlot { leaf, words, commit, proof, path }
}
fn source_domain(builder: &mut CircuitBuilder<F, 2>, label: &[u8]) -> Bytes32Target {
    let mut keccak = tiny_keccak::Keccak::v256();
    keccak.update(b"PsyBridge/SourceCheckpointReward/1/");
    keccak.update(label);
    let mut digest = [0u8; 32];
    keccak.finalize(&mut digest);
    hash::constant_bytes32(builder, digest)
}

fn source_checkpoint_reward_leaf_commit(builder: &mut CircuitBuilder<F, 2>, body: &[Target]) -> Bytes32Target {
    let mut preimage = source_domain(builder, b"Leaf").to_vec();
    preimage.extend_from_slice(body);
    psy_plonky2_common_circuits::hash::keccak::keccak256_u32_words_be_abi(builder, &preimage).map(|word| word.0)
}


fn bytes32_to_bytes(builder: &mut CircuitBuilder<F, 2>, words: Bytes32Target) -> [Target; 32] {
    let mut bytes = [builder.zero(); 32];
    for (index, word) in words.into_iter().enumerate() {
        let raw = raw_u32_bytes(builder, word);
        bytes[index * 4] = raw[3];
        bytes[index * 4 + 1] = raw[2];
        bytes[index * 4 + 2] = raw[1];
        bytes[index * 4 + 3] = raw[0];
    }
    bytes
}

fn amount_words(builder: &mut CircuitBuilder<F, 2>, amount: &[Target; 8]) -> [Target; 8] {
    std::array::from_fn(|index| {
        let limb = amount[7 - index];
        builder.range_check(limb, 32);
        hash::word(&mut *builder, limb, 32)[7]
    })
}

fn reward_ledger_window(
    builder: &mut CircuitBuilder<F, 2>, config: &NetworkConfigTarget, verifier: &VerifierCircuitTarget,
) -> (RewardLedgerWindowTargets, Bytes32Target, Bytes32Target, HashOutTarget) {
    let config_words = config.hash(builder);
    let window_words = builder.add_virtual_target_arr();
    for word in window_words { builder.range_check(word, 32); }
    let config_hash = bytes32_to_bytes(builder, config_words);
    let window_id = bytes32_to_bytes(builder, window_words);
    let economic_domain = builder.add_virtual_target_arr();
    let start_root = builder.add_virtual_hash();
    let end_checkpoint_id = builder.add_virtual_target();
    builder.range_check(end_checkpoint_id, 32);
    let end_checkpoint_root = builder.add_virtual_hash();
    hash::encode_hash4(builder, end_checkpoint_root.elements);
    let old_ledger_state_root = builder.add_virtual_hash();
    hash::encode_hash4(builder, old_ledger_state_root.elements);
    let (verifier_hash, hash) = reward_ledger_window_hash(builder, &config_hash, &economic_domain, &window_id,
        end_checkpoint_id, end_checkpoint_root, start_root, verifier);
    (RewardLedgerWindowTargets { config_hash, economic_domain, window_id, end_checkpoint_id, end_checkpoint_root, start_root, verifier_hash, hash }, config_words, window_words, old_ledger_state_root)
}

fn constrain_reward_payout(
    builder: &mut CircuitBuilder<F, 2>, index: usize, count: Target, previous_user: Option<Target>,
    common: &CommonCircuitData<F, 2>, real_vk: &VerifierCircuitTarget, dummy_proof: &ProofWithPublicInputsTarget<2>,
    dummy_vk: &VerifierCircuitTarget, ledger_window: &RewardLedgerWindowTargets, ledger_final_user_root: HashOutTarget,
) -> RewardPayoutSlot {
    let zero = builder.zero();
    let one = builder.one();
    let slot = builder.constant(F::from_canonical_usize(index));
    let active = builder.is_less_than(REWARD_CHUNK_SLOTS.ilog2() as usize + 1, slot, count);
    let inactive = builder.not(active);
    let proof = builder.add_virtual_proof_with_pis(common);
    builder.conditionally_verify_proof::<PoseidonGoldilocksConfig>(active, &proof, real_vk, dummy_proof, dummy_vk, common);
    for &word in &proof.public_inputs { builder.connect_if_true(inactive, word, zero); }
    let state = RewardLedgerStateTargets::new(builder);
    for target in state.ledger_window_hash.elements.into_iter().chain(state.ledger_root.elements).chain(state.user_root.elements) {
        builder.connect_if_true(inactive, target, zero);
    }
    builder.connect_if_true(inactive, state.session_count, zero);
    builder.connect_if_true(inactive, state.unfinished_session_count, zero);
    builder.connect_hashes_if_true(active, state.ledger_window_hash, ledger_window.hash);
    let proof_root = HashOutTarget { elements: std::array::from_fn(|i| proof.public_inputs[30 + i]) };
    builder.connect_hashes_if_true(active, state.root, proof_root);
    builder.connect_hashes_if_true(active, HashOutTarget { elements: std::array::from_fn(|i| proof.public_inputs[i]) }, ledger_window.end_checkpoint_root);
    let user_id = proof.public_inputs[4];
    if let Some(previous) = previous_user {
        let increasing = builder.is_less_than(32, previous, user_id);
        builder.connect_if_true(active, increasing.target, one);
    }
    for index in 10..13 { builder.connect_if_true(active, proof.public_inputs[index], zero); }
    let mut recipient_zero = builder._true();
    for word in &proof.public_inputs[5..10] {
        let equal = builder.is_equal(*word, zero);
        recipient_zero = builder.and(recipient_zero, equal);
    }
    let recipient_nonzero = builder.not(recipient_zero);
    builder.connect_if_true(active, recipient_nonzero.target, one);
    let mut amount_zero = builder._true();
    for word in &proof.public_inputs[13..21] {
        let equal = builder.is_equal(*word, zero);
        amount_zero = builder.and(amount_zero, equal);
    }
    let amount_nonzero = builder.not(amount_zero);
    builder.connect_if_true(active, amount_nonzero.target, one);
    let count_zero = builder.is_equal(proof.public_inputs[21], zero);
    let count_nonzero = builder.not(count_zero);
    builder.connect_if_true(active, count_nonzero.target, one);
    let source_checkpoint_id = builder.add_virtual_target();
    let source_index = builder.select(active, source_checkpoint_id, zero);
    builder.range_check(source_index, 32);
    let source_leaf = PsyCheckpointLeafGadget::create_virtual(builder);
    for target in source_leaf.to_targets() { builder.connect_if_true(inactive, target, zero); }
    let source_root = builder.add_virtual_hash();
    let source = historical_merkle_proof(builder, [source_index, zero], &source_leaf, [ledger_window.end_checkpoint_id, zero], source_root);
    builder.connect_hashes_if_true(active, source.path.root, ledger_window.end_checkpoint_root);
    for sibling in &source.path.siblings { for target in sibling.elements { builder.connect_if_true(inactive, target, zero); } }
    let session_root = builder.add_virtual_hash();
    for target in session_root.elements { builder.connect_if_true(inactive, target, zero); }
    let summary_siblings = std::array::from_fn(|_| builder.add_virtual_hash());
    for sibling in &summary_siblings { for target in sibling.elements { builder.connect_if_true(inactive, target, zero); } }
    let recipient = std::array::from_fn(|i| proof.public_inputs[5 + i]);
    let seed = reward_session_seed(builder, &ledger_window.economic_domain, source_index, user_id, &recipient, ledger_window.end_checkpoint_root, source.checkpoint_leaf_hash);
    let final_step = builder._true();
    let summary = reward_session_summary(builder, &proof.public_inputs, seed, session_root, final_step);
    let summary_root = summary_path_root(builder, user_id, summary, &summary_siblings);
    builder.connect_hashes_if_true(active, summary_root, ledger_final_user_root);
    let mut encoded = Vec::with_capacity(48);
    for chunk in ledger_window.economic_domain.chunks(4) {
        let mut word = builder.zero();
        for byte in chunk { word = builder.mul_const_add(F::from_canonical_u32(256), word, *byte); }
        encoded.push(word);
    }
    encoded.extend(hash::word(builder, source_index, 32));
    encoded.extend(hash::word(builder, user_id, 32));
    encoded.extend(amount_words(builder, &std::array::from_fn(|i| proof.public_inputs[13 + i])));
    encoded.extend(hash::word_address(builder, recipient));
    encoded.extend(hash::word(builder, one, 1));
    let leaf_words = std::array::from_fn(|index| builder.select(active, encoded[index], zero));
    let raw_commit = source_checkpoint_reward_leaf_commit(builder, &encoded);
    let commit = std::array::from_fn(|index| builder.select(active, raw_commit[index], zero));
    RewardPayoutSlot { proof, state, source_checkpoint_id, source, session_root, summary_siblings, leaf_words, commit }
}

struct RewardAggregateNodeTargets {
    ledger_window_hash: HashOutTarget,
    new_ledger_state_root: HashOutTarget,
    ledger_final_user_root: HashOutTarget,
    total_count: Target,
    first_ordinal: Target,
    count: Target,
    first_user: Target,
    last_user: Target,
    claim_root: Bytes32Target,
    incoming: KeccakStreamTargets,
    outgoing: KeccakStreamTargets,
}

struct RewardInclusionChunkCircuit {
    circuit_data: CircuitData<F, PoseidonGoldilocksConfig, 2>,
    config: NetworkConfigTarget,
    config_hash: Bytes32Target,
    window_id: Bytes32Target,
    economic_domain: [Target; 32],
    start_root: HashOutTarget,
    end_id: Target,
    end_root: HashOutTarget,
    old_ledger_state_root: HashOutTarget,
    final_state: RewardLedgerStateTargets,
    total_count: Target,
    first_ordinal: Target,
    incoming: KeccakStreamTargets,
    dummy_proof: ProofWithPublicInputsTarget<2>,
    slots: [RewardPayoutSlot; REWARD_CHUNK_SLOTS],
}

struct RewardInclusionCombineCircuit {
    circuit_data: CircuitData<F, PoseidonGoldilocksConfig, 2>,
    left: ProofWithPublicInputsTarget<2>,
    right: ProofWithPublicInputsTarget<2>,
}

fn virtual_stream(builder: &mut CircuitBuilder<F, 2>) -> KeccakStreamTargets {
    KeccakStreamTargets {
        state: std::array::from_fn(|_| [U32Target(builder.add_virtual_target()), U32Target(builder.add_virtual_target())]),
        byte_offset: builder.add_virtual_target(),
    }
}

fn constant_stream(builder: &mut CircuitBuilder<F, 2>, stream: &KeccakStreamValues) -> KeccakStreamTargets {
    KeccakStreamTargets {
        state: std::array::from_fn(|lane| std::array::from_fn(|half| U32Target(builder.constant(F::from_canonical_u32(stream.state[lane][half]))))),
        byte_offset: builder.constant(F::from_canonical_u8(stream.byte_offset)),
    }
}

fn connect_stream(builder: &mut CircuitBuilder<F, 2>, left: &KeccakStreamTargets, right: &KeccakStreamTargets) {
    for (left_lane, right_lane) in left.state.iter().zip(&right.state) {
        builder.connect(left_lane[0].0, right_lane[0].0);
        builder.connect(left_lane[1].0, right_lane[1].0);
    }
    builder.connect(left.byte_offset, right.byte_offset);
}

fn subtract_clamped(builder: &mut CircuitBuilder<F, 2>, value: Target, bound: Target) -> Target {
    let below = builder.is_less_than(32, value, bound);
    let difference = builder.sub(value, bound);
    let zero = builder.zero();
    builder.select(below, zero, difference)
}

fn register_node(builder: &mut CircuitBuilder<F, 2>, level: usize, node: &RewardAggregateNodeTargets) {
    let prefix = [1u32, REWARD_AGGREGATE_NODE_FAMILY as u32, REWARD_AGGREGATE_NODE_VARIANT as u32, level as u32]
        .map(|value| builder.constant(F::from_canonical_u32(value)));
    builder.register_public_inputs(&prefix);
    builder.register_public_inputs(&node.ledger_window_hash.elements);
    builder.register_public_inputs(&node.new_ledger_state_root.elements);
    builder.register_public_inputs(&node.ledger_final_user_root.elements);
    builder.register_public_input(node.total_count);
    builder.register_public_input(node.first_ordinal);
    builder.register_public_input(node.count);
    builder.register_public_input(node.first_user);
    builder.register_public_input(node.last_user);
    builder.register_public_inputs(&node.claim_root);
    for lane in &node.incoming.state {
        builder.register_public_input(lane[0].0);
        builder.register_public_input(lane[1].0);
    }
    builder.register_public_input(node.incoming.byte_offset);
    for lane in &node.outgoing.state {
        builder.register_public_input(lane[0].0);
        builder.register_public_input(lane[1].0);
    }
    builder.register_public_input(node.outgoing.byte_offset);
}

fn checked_node_prefix(builder: &mut CircuitBuilder<F, 2>, proof: &ProofWithPublicInputsTarget<2>, level: usize) -> RewardAggregateNodeTargets {
    let inputs = &proof.public_inputs;
    for (target, value) in inputs[..4].iter().zip([1u32, REWARD_AGGREGATE_NODE_FAMILY as u32, REWARD_AGGREGATE_NODE_VARIANT as u32, level as u32]) {
        let expected = builder.constant(F::from_canonical_u32(value));
        builder.connect(*target, expected);
    }
    RewardAggregateNodeTargets {
        ledger_window_hash: HashOutTarget { elements: std::array::from_fn(|index| inputs[4 + index]) },
        new_ledger_state_root: HashOutTarget { elements: std::array::from_fn(|index| inputs[8 + index]) },
        ledger_final_user_root: HashOutTarget { elements: std::array::from_fn(|index| inputs[12 + index]) },
        total_count: inputs[16],
        first_ordinal: inputs[17],
        count: inputs[18],
        first_user: inputs[19],
        last_user: inputs[20],
        claim_root: std::array::from_fn(|index| inputs[21 + index]),
        incoming: KeccakStreamTargets {
            state: std::array::from_fn(|lane| [U32Target(inputs[29 + lane * 2]), U32Target(inputs[30 + lane * 2])]),
            byte_offset: inputs[79],
        },
        outgoing: KeccakStreamTargets {
            state: std::array::from_fn(|lane| [U32Target(inputs[80 + lane * 2]), U32Target(inputs[81 + lane * 2])]),
            byte_offset: inputs[130],
        },
    }
}

fn node_registration(level: u8, data: &CircuitData<F, PoseidonGoldilocksConfig, 2>) -> anyhow::Result<CircuitSetRegistration> {
    anyhow::ensure!(data.common.num_public_inputs == REWARD_AGGREGATE_NODE_PI_LEN, "reward hierarchy public-input width mismatch");
    let fingerprint = get_circuit_fingerprint_generic_q::<2, F, PoseidonGoldilocksConfig>(&data.verifier_only).to_u64x4();
    anyhow::ensure!(fingerprint != [0; 4], "missing reward hierarchy pin");
    let digest = |bytes: &[u8]| {
        let mut hasher = tiny_keccak::Keccak::v256();
        hasher.update(bytes);
        let mut result = [0u8; 32];
        hasher.finalize(&mut result);
        result
    };
    Ok(CircuitSetRegistration {
        family: REWARD_AGGREGATE_NODE_FAMILY as u16, level, variant: REWARD_AGGREGATE_NODE_VARIANT,
        pi_words: REWARD_AGGREGATE_NODE_PI_LEN as u16, fingerprint,
        common_digest: digest(&data.common.to_bytes(&PsyGateSerializer).map_err(|error| anyhow::anyhow!("common serialization: {error:?}"))?),
        verifier_digest: digest(&data.verifier_only.to_bytes().map_err(|error| anyhow::anyhow!("verifier serialization: {error:?}"))?),
        identity_fingerprint: [0; 4],
    })
}

fn verifier_data(data: &CircuitData<F, PoseidonGoldilocksConfig, 2>) -> VerifierCircuitData<F, PoseidonGoldilocksConfig, 2> {
    VerifierCircuitData { verifier_only: data.verifier_only.clone(), common: data.common.clone() }
}
#[cfg(test)]
fn proc_status_field(phase: &str, name: &str) -> anyhow::Result<String> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|error| anyhow::anyhow!("reward phase status: {error}"))?;
    status.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key == name).then(|| value.trim().to_string())
    }).ok_or_else(|| anyhow::anyhow!("reward phase {phase} missing {name}"))
}
#[cfg(test)]
fn report_chunk_phase(builder: &CircuitBuilder<F, 2>, started: std::time::Instant, phase: &str) -> anyhow::Result<()> {
    eprintln!(
        "[reward-constructor] phase={phase} elapsed_ms={} gates={} vm_rss={} vm_hwm={}",
        started.elapsed().as_millis(), builder.num_gates(), proc_status_field(phase, "VmRSS")?, proc_status_field(phase, "VmHWM")?,
    );
    Ok(())
}
#[cfg(test)]
fn report_prove_phase(started: std::time::Instant, phase: &str) -> anyhow::Result<()> {
    eprint!("[reward-prove] phase={phase} elapsed_ms={}", started.elapsed().as_millis());
    std::io::Write::flush(&mut std::io::stderr())?;
    let rss = proc_status_field(phase, "VmRSS")?;
    let hwm = proc_status_field(phase, "VmHWM")?;
    eprintln!(" vm_rss={rss} vm_hwm={hwm}");
    std::io::Write::flush(&mut std::io::stderr())?;
    Ok(())
}

impl RewardInclusionChunkCircuit {
    fn new(common: &CommonCircuitData<F, 2>, verifier: &VerifierOnlyCircuitData<PoseidonGoldilocksConfig, 2>, source_chain_count: usize) -> anyhow::Result<Self> {
        anyhow::ensure!((1..=8).contains(&source_chain_count), "reward source chain count is outside 1..=8");
        anyhow::ensure!(common.num_public_inputs == REWARD_SESSION_PROOF_FIELD_COUNT, "reward session width mismatch");
        #[cfg(test)]
        eprintln!("[reward-constructor] phase=chunk-new-entry");
        #[cfg(test)]
        let started = std::time::Instant::now();
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let config = NetworkConfigTarget::new(&mut builder, source_chain_count);
        let real_vk = builder.constant_verifier_data(verifier);
        let (ledger_window, config_words, window_words, old_ledger_state_root) = reward_ledger_window(&mut builder, &config, &real_vk);
        builder.connect_hashes(ledger_window.start_root, old_ledger_state_root);
        let total_count = builder.add_virtual_target();
        let first_ordinal = builder.add_virtual_target();
        builder.range_check(total_count, 32);
        builder.range_check(first_ordinal, 32);
        let publication_limit = builder.constant(F::from_canonical_usize(REWARD_PUBLICATION_CAPACITY));
        builder.ensure_is_less_than_or_equal(32, total_count, publication_limit);
        builder.ensure_is_less_than_or_equal(32, total_count, config.max_rewards);
        let span = builder.constant(F::from_canonical_usize(REWARD_CHUNK_SLOTS));
        let mut matched = builder._false();
        for candidate in 0..REWARD_PUBLICATION_CAPACITY / REWARD_CHUNK_SLOTS {
            let value = builder.constant(F::from_canonical_usize(candidate));
            let aligned = builder.mul(value, span);
            let equal = builder.is_equal(first_ordinal, aligned);
            matched = builder.or(matched, equal);
        }
        let one = builder.one();
        builder.connect(matched.target, one);
        let remaining = subtract_clamped(&mut builder, total_count, first_ordinal);
        let partial = builder.is_less_than(32, remaining, span);
        let count = builder.select(partial, remaining, span);
        let zero = builder.zero();
        let empty = builder.is_equal(count, zero);
        let (dummy_proof, dummy_vk) = builder.dummy_proof_and_constant_vk_no_generator::<PoseidonGoldilocksConfig>(common)
            .map_err(|error| anyhow::anyhow!("reward chunk dummy target: {error:?}"))?;
        let final_state = RewardLedgerStateTargets::new(&mut builder);
        let window_empty = builder.is_equal(total_count, zero);
        let nonempty_window = builder.not(window_empty);
        builder.connect_hashes_if_true(nonempty_window, final_state.ledger_window_hash, ledger_window.hash);
        builder.connect_if_true(nonempty_window, final_state.session_count, total_count);
        builder.connect_if_true(nonempty_window, final_state.unfinished_session_count, zero);
        #[cfg(test)]
        report_chunk_phase(&builder, started, "chunk-shared-setup")?;
        let mut previous_user = None;
        let mut slots = Vec::with_capacity(REWARD_CHUNK_SLOTS);
        for index in 0..REWARD_CHUNK_SLOTS {
            slots.push(constrain_reward_payout(&mut builder, index, count, previous_user, common, &real_vk, &dummy_proof, &dummy_vk, &ledger_window, final_state.user_root));
            previous_user = Some(slots[index].proof.public_inputs[4]);
            #[cfg(test)]
            report_chunk_phase(&builder, started, &format!("chunk-payout-slot index={index}"))?;
        }
        let mut first_user = zero;
        let mut last_user = zero;
        for (index, slot) in slots.iter().enumerate() {
            let position = builder.constant(F::from_canonical_usize(index));
            let next = builder.constant(F::from_canonical_usize(index + 1));
            let not_empty = builder.not(empty);
            let at_zero = builder.is_equal(position, zero);
            let is_first = builder.and(not_empty, at_zero);
            let is_last = builder.is_equal(next, count);
            first_user = builder.select(is_first, slot.proof.public_inputs[4], first_user);
            last_user = builder.select(is_last, slot.proof.public_inputs[4], last_user);
        }
        builder.connect_if_true(empty, first_user, zero);
        builder.connect_if_true(empty, last_user, zero);
        let mut nodes = Vec::with_capacity(REWARD_CHUNK_SLOTS);
        for (index, slot) in slots.iter().enumerate() {
            let position = builder.constant(F::from_canonical_usize(index));
            let ordinal = builder.add(first_ordinal, position);
            let real = builder.is_less_than(REWARD_CHUNK_SLOTS.ilog2() as usize + 1, position, count);
            let leaf = claim_leaf(&mut builder, total_count, ordinal, slot.commit);
            let empty_leaf = claim_empty(&mut builder, total_count, ordinal);
            nodes.push(std::array::from_fn(|word| builder.select(real, leaf[word], empty_leaf[word])));
        }
        #[cfg(test)]
        report_chunk_phase(&builder, started, "chunk-claim-leaves")?;
        for level in 1..=REWARD_CHUNK_SLOTS.trailing_zeros() {
            nodes = nodes.chunks_exact(2).map(|pair| claim_parent(&mut builder, level, pair[0], pair[1])).collect();
        }
        #[cfg(test)]
        report_chunk_phase(&builder, started, "chunk-claim-parents")?;
        let incoming = virtual_stream(&mut builder);
        let mut stream = incoming;
        for call in 0..REWARD_CHUNK_ABSORB_CALLS {
            let start = 136 * call;
            let mut words = [zero; 34];
            for (slot_index, slot) in slots.iter().enumerate() {
                for (word_index, &word) in slot.leaf_words.iter().enumerate() {
                    let byte_start = slot_index * SOURCE_CHECKPOINT_REWARD_LEAF_BYTES + word_index * 4;
                    if byte_start + 4 <= start || byte_start >= start + 136 { continue; }
                    let destination = (byte_start - start) / 4;
                    words[destination] = word;
                }
            }
            let produced = builder.mul_const(F::from_canonical_usize(SOURCE_CHECKPOINT_REWARD_LEAF_BYTES), count);
            let consumed = builder.constant(F::from_canonical_usize(start));
            let available = subtract_clamped(&mut builder, produced, consumed);
            let rate = builder.constant(F::from_canonical_usize(136));
            let clipped = builder.is_less_than(32, available, rate);
            let byte_length = builder.select(clipped, available, rate);
            stream = keccak_stream_absorb(&mut builder, stream, &words, byte_length);
            #[cfg(test)]
            report_chunk_phase(&builder, started, &format!("chunk-stream-absorb call={call}"))?;
        }
        let node = RewardAggregateNodeTargets {
            ledger_window_hash: ledger_window.hash, new_ledger_state_root: final_state.root,
            ledger_final_user_root: final_state.user_root, total_count, first_ordinal, count, first_user, last_user,
            claim_root: nodes[0], incoming, outgoing: stream,
        };
        register_node(&mut builder, 0, &node);
        #[cfg(test)]
        report_chunk_phase(&builder, started, "chunk-before-build")?;
        #[cfg(test)]
        eprintln!("[reward-constructor] phase=chunk-build-entry");
        let circuit_data = builder.build::<PoseidonGoldilocksConfig>();
        #[cfg(test)]
        eprintln!("[reward-constructor] phase=chunk-build elapsed_ms={}", started.elapsed().as_millis());
        anyhow::ensure!(circuit_data.common.num_public_inputs == REWARD_AGGREGATE_NODE_PI_LEN, "reward chunk width mismatch");

        let slots = slots.try_into().map_err(|_| anyhow::anyhow!("reward chunk slot width mismatch"))?;
        Ok(Self {
            circuit_data, config, config_hash: config_words, window_id: window_words,
            economic_domain: ledger_window.economic_domain, start_root: ledger_window.start_root,
            end_id: ledger_window.end_checkpoint_id, end_root: ledger_window.end_checkpoint_root, old_ledger_state_root,
            final_state, total_count, first_ordinal, incoming: node.incoming, dummy_proof, slots,
        })
    }
}

impl RewardInclusionCombineCircuit {
    fn new(level: usize, child: &VerifierCircuitData<F, PoseidonGoldilocksConfig, 2>) -> anyhow::Result<Self> {
        anyhow::ensure!((1..REWARD_HIERARCHY_LEVELS).contains(&level), "reward combine level is outside 1..=8");
        anyhow::ensure!(child.common.num_public_inputs == REWARD_AGGREGATE_NODE_PI_LEN, "reward child width mismatch");
        #[cfg(test)]
        eprintln!("[reward-constructor] phase=combine-new-entry level={level}");
        #[cfg(test)]
        let started = std::time::Instant::now();
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let verifier = builder.constant_verifier_data(&child.verifier_only);
        let left_proof = builder.add_virtual_proof_with_pis(&child.common);
        let right_proof = builder.add_virtual_proof_with_pis(&child.common);
        builder.verify_proof::<PoseidonGoldilocksConfig>(&left_proof, &verifier, &child.common);
        builder.verify_proof::<PoseidonGoldilocksConfig>(&right_proof, &verifier, &child.common);
        let left = checked_node_prefix(&mut builder, &left_proof, level - 1);
        let right = checked_node_prefix(&mut builder, &right_proof, level - 1);
        builder.connect_hashes(left.ledger_window_hash, right.ledger_window_hash);
        builder.connect_hashes(left.new_ledger_state_root, right.new_ledger_state_root);
        builder.connect_hashes(left.ledger_final_user_root, right.ledger_final_user_root);
        builder.connect(left.total_count, right.total_count);
        let span = builder.constant(F::from_canonical_usize(REWARD_CHUNK_SLOTS << level));
        let half = builder.constant(F::from_canonical_usize(REWARD_CHUNK_SLOTS << (level - 1)));
        let mut matched = builder._false();
        for candidate in 0..REWARD_PUBLICATION_CAPACITY / (REWARD_CHUNK_SLOTS << level) {
            let value = builder.constant(F::from_canonical_usize(candidate));
            let aligned = builder.mul(value, span);
            let equal = builder.is_equal(left.first_ordinal, aligned);
            matched = builder.or(matched, equal);
        }
        let one = builder.one();
        builder.connect(matched.target, one);
        let right_first = builder.add(left.first_ordinal, half);
        builder.connect(right.first_ordinal, right_first);
        let left_remaining = subtract_clamped(&mut builder, left.total_count, left.first_ordinal);
        let right_remaining = subtract_clamped(&mut builder, right.total_count, right.first_ordinal);
        let left_partial = builder.is_less_than(32, left_remaining, half);
        let right_partial = builder.is_less_than(32, right_remaining, half);
        let left_count = builder.select(left_partial, left_remaining, half);
        builder.connect(left.count, left_count);
        let right_count = builder.select(right_partial, right_remaining, half);
        builder.connect(right.count, right_count);
        let parent_remaining = subtract_clamped(&mut builder, left.total_count, left.first_ordinal);
        let parent_partial = builder.is_less_than(32, parent_remaining, span);
        let count = builder.select(parent_partial, parent_remaining, span);
        let summed = builder.add(left.count, right.count);
        builder.connect(count, summed);
        let zero = builder.zero();
        let left_empty = builder.is_equal(left.count, zero);
        let right_empty = builder.is_equal(right.count, zero);
        builder.connect_if_true(left_empty, left.first_user, zero);
        builder.connect_if_true(left_empty, left.last_user, zero);
        builder.connect_if_true(right_empty, right.first_user, zero);
        builder.connect_if_true(right_empty, right.last_user, zero);
        let left_nonempty = builder.not(left_empty);
        let right_nonempty = builder.not(right_empty);
        let both = builder.and(left_nonempty, right_nonempty);
        let ordered = builder.is_less_than(32, left.last_user, right.first_user);
        builder.connect_if_true(both, ordered.target, one);
        let first_user = builder.select(left_empty, right.first_user, left.first_user);
        let last_user = builder.select(right_empty, left.last_user, right.last_user);
        connect_stream(&mut builder, &left.outgoing, &right.incoming);
        let claim_root = claim_parent(&mut builder, REWARD_CHUNK_SLOTS.trailing_zeros() + level as u32, left.claim_root, right.claim_root);
        let node = RewardAggregateNodeTargets {
            ledger_window_hash: left.ledger_window_hash, new_ledger_state_root: left.new_ledger_state_root,
            ledger_final_user_root: left.ledger_final_user_root, total_count: left.total_count,
            first_ordinal: left.first_ordinal, count, first_user, last_user, claim_root,
            incoming: left.incoming, outgoing: right.outgoing,
        };
        register_node(&mut builder, level, &node);
        #[cfg(test)]
        eprintln!("[reward-constructor] phase=combine-build-entry level={level}");
        let circuit_data = builder.build::<PoseidonGoldilocksConfig>();
        #[cfg(test)]
        eprintln!("[reward-constructor] phase=combine-build level={level} elapsed_ms={}", started.elapsed().as_millis());
        anyhow::ensure!(circuit_data.common.num_public_inputs == REWARD_AGGREGATE_NODE_PI_LEN, "reward combine width mismatch");
        Ok(Self { circuit_data, left: left_proof, right: right_proof })
    }

    fn prove(&self, left: ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>, right: ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>) -> anyhow::Result<ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>> {
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(&self.left, &left)?;
        witness.set_proof_with_pis_target(&self.right, &right)?;
        drop(left);
        drop(right);
        self.circuit_data.prove(witness)
    }
}

fn set_stream(witness: &mut PartialWitness<F>, target: &KeccakStreamTargets, value: &KeccakStreamValues) -> anyhow::Result<()> {
    for (lane_target, lane) in target.state.iter().zip(value.state) {
        witness.set_target(lane_target[0].0, F::from_canonical_u32(lane[0]))?;
        witness.set_target(lane_target[1].0, F::from_canonical_u32(lane[1]))?;
    }
    witness.set_target(target.byte_offset, F::from_canonical_u8(value.byte_offset))
}

fn stream_from_proof(proof: &ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>, outgoing: bool) -> anyhow::Result<KeccakStreamValues> {
    let base = if outgoing { 80 } else { 29 };
    let inputs = &proof.public_inputs;
    anyhow::ensure!(inputs.len() == REWARD_AGGREGATE_NODE_PI_LEN, "reward node width mismatch");
    let state = std::array::from_fn(|lane| [
        inputs[base + lane * 2].to_canonical_u64() as u32,
        inputs[base + lane * 2 + 1].to_canonical_u64() as u32,
    ]);
    Ok(KeccakStreamValues { state, byte_offset: inputs[base + 50].to_canonical_u64() as u8 })
}


impl RewardInclusionChunkCircuit {
    fn prove(
        &self, config: &NetworkConfig, header: &InclusionAggregateHeader, final_state: &RewardLedgerStateValues,
        first_ordinal: u32, incoming: &KeccakStreamValues, leaves: &[SourceCheckpointRewardAggregateLeaf<'_>],
        retained_dummy_proof: &ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>,
        inactive_slot_proof: &ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>> {
        anyhow::ensure!(leaves.len() <= REWARD_CHUNK_SLOTS, "reward chunk exceeds 4 slots");
        let mut witness = PartialWitness::new();
        self.config.set_witness(&mut witness, config)?;
        set_bytes(&mut witness, &self.config_hash, &header.config_hash)?;
        set_bytes(&mut witness, &self.window_id, &header.window_id)?;
        let economic_domain = config.clone().load()?.economic_domain();
        anyhow::ensure!(leaves.iter().all(|leaf| leaf.leaf.economic_domain == economic_domain), "reward economic domain differs inside one chunk");
        for (target, byte) in self.economic_domain.iter().zip(economic_domain) { witness.set_target(*target, F::from_canonical_u8(byte))?; }
        let old_root = header.old_ledger_state_root.ok_or_else(|| anyhow::anyhow!("reward publication ledger-state roots missing"))?;
        set_hash4(&mut witness, self.start_root.elements, old_root)?;
        witness.set_target(self.end_id, F::from_canonical_u32(header.end_checkpoint_id as u32))?;
        set_hash4(&mut witness, self.end_root.elements, header.end_checkpoint_root)?;
        set_hash4(&mut witness, self.old_ledger_state_root.elements, old_root)?;
        self.final_state.set_witness(&mut witness, final_state)?;
        witness.set_target(self.total_count, F::from_canonical_u32(header.total_count))?;
        witness.set_target(self.first_ordinal, F::from_canonical_u32(first_ordinal))?;
        set_stream(&mut witness, &self.incoming, incoming)?;
        witness.set_proof_with_pis_target(&self.dummy_proof, retained_dummy_proof)?;
        let empty_leaf = PsyCheckpointLeaf::default();
        let zero_state = RewardLedgerStateValues { ledger_window_hash: [0; 4], ledger_root: [0; 4], user_root: [0; 4], session_count: 0, unfinished_session_count: 0 };
        for (index, slot) in self.slots.iter().enumerate() {
            if let Some(leaf) = leaves.get(index) {
                anyhow::ensure!(leaf.proof.public_inputs.len() == REWARD_SESSION_PROOF_FIELD_COUNT, "reward leaf width mismatch");
                anyhow::ensure!(leaf.leaf.source_checkpoint_id == u64::from(leaf.source_checkpoint_id), "reward source checkpoint differs from leaf");
                set_bytes(&mut witness, &slot.leaf_words, &leaf.leaf.encode()?)?;
                witness.set_proof_with_pis_target(&slot.proof, leaf.proof)?;
                slot.state.set_witness(&mut witness, leaf.state)?;
                witness.set_target(slot.source_checkpoint_id, F::from_canonical_u32(leaf.source_checkpoint_id))?;
                slot.source.checkpoint_leaf.set_witness(&mut witness, leaf.source_leaf)?;
                for (target, sibling) in slot.source.path.siblings.iter().zip(leaf.source_siblings) { set_hash4(&mut witness, target.elements, *sibling)?; }
                set_hash4(&mut witness, slot.session_root.elements, leaf.session_root)?;
                for (target, sibling) in slot.summary_siblings.iter().zip(leaf.summary_siblings) { set_hash4(&mut witness, target.elements, *sibling)?; }
            } else {
                set_bytes(&mut witness, &slot.leaf_words, &[0u8; SOURCE_CHECKPOINT_REWARD_LEAF_BYTES])?;
                witness.set_proof_with_pis_target(&slot.proof, inactive_slot_proof)?;
                slot.state.set_witness(&mut witness, &zero_state)?;
                witness.set_target(slot.source_checkpoint_id, F::ZERO)?;
                slot.source.checkpoint_leaf.set_witness(&mut witness, &empty_leaf)?;
                for sibling in slot.source.path.siblings.iter().chain(&slot.summary_siblings) { set_hash4(&mut witness, sibling.elements, [0; 4])?; }
                set_hash4(&mut witness, slot.session_root.elements, [0; 4])?;
            }
        }
        self.circuit_data.prove(witness)
    }
}

fn opening_prefix_stream(header: &InclusionAggregateHeader) -> anyhow::Result<KeccakStreamValues> {
    let mut bytes = source_domain_bytes(b"Opening").to_vec();
    bytes.extend(header.config_hash);
    bytes.extend(header.window_id);
    bytes.extend([0u8; 24]);
    bytes.extend(header.end_checkpoint_id.to_be_bytes());
    for limb in header.end_checkpoint_root {
        bytes.extend([0u8; 24]);
        bytes.extend(limb.to_be_bytes());
    }
    bytes.extend([0u8; 28]);
    bytes.extend(header.total_count.to_be_bytes());
    anyhow::ensure!(bytes.len() == 288, "reward opening prefix width mismatch");
    let mut stream = KeccakStreamValues::default();
    for (call, length) in [(0usize, 136usize), (1, 136), (2, 16)] {
        let start = 136 * call;
        let mut words = [0u32; 34];
        for (index, chunk) in bytes[start..start + length].chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        keccak_stream_absorb_values(&mut stream, &words, length)?;
    }
    Ok(stream)
}

fn source_domain_bytes(label: &[u8]) -> [u8; 32] {
    let mut keccak = tiny_keccak::Keccak::v256();
    keccak.update(b"PsyBridge/SourceCheckpointReward/1/");
    keccak.update(label);
    let mut digest = [0u8; 32];
    keccak.finalize(&mut digest);
    digest
}

impl RewardInclusionAggregateCircuit {
    pub fn new(common: &CommonCircuitData<F, 2>, verifier: &VerifierOnlyCircuitData<PoseidonGoldilocksConfig, 2>, source_chain_count: usize) -> anyhow::Result<Self> {
        anyhow::ensure!((1..=8).contains(&source_chain_count), "reward source chain count is outside 1..=8");
        anyhow::ensure!(REWARD_CHUNK_SLOTS.is_power_of_two(), "reward chunk slots are not a power of two");
        anyhow::ensure!(REWARD_PUBLICATION_CAPACITY % REWARD_CHUNK_SLOTS == 0, "reward publication capacity is not a multiple of chunk slots");
        anyhow::ensure!(
            REWARD_HIERARCHY_LEVELS == 1 + (REWARD_PUBLICATION_CAPACITY / REWARD_CHUNK_SLOTS).trailing_zeros() as usize,
            "reward hierarchy levels do not cover the chunk tree",
        );
        anyhow::ensure!(
            REWARD_CHUNK_SLOTS.trailing_zeros() + REWARD_HIERARCHY_LEVELS as u32 - 1 == REWARD_PUBLICATION_CAPACITY.trailing_zeros(),
            "reward claim depth does not reach the publication tree",
        );
        anyhow::ensure!(common.num_public_inputs == REWARD_SESSION_PROOF_FIELD_COUNT, "reward session width mismatch");
        #[cfg(test)]
        let started = std::time::Instant::now();
        let mut nodes = Vec::with_capacity(REWARD_HIERARCHY_LEVELS);
        let mut registrations = Vec::with_capacity(REWARD_HIERARCHY_LEVELS);
        let chunk = RewardInclusionChunkCircuit::new(common, verifier, source_chain_count)?;
        registrations.push(node_registration(0, &chunk.circuit_data)?);
        nodes.push(verifier_data(&chunk.circuit_data));
        drop(chunk);
        #[cfg(test)]
        eprintln!("[reward-constructor] phase=adapter-chunk elapsed_ms={}", started.elapsed().as_millis());
        for level in 1..REWARD_HIERARCHY_LEVELS {
            #[cfg(test)]
            let level_started = std::time::Instant::now();
            let combine = RewardInclusionCombineCircuit::new(level, &nodes[level - 1])?;
            registrations.push(node_registration(level as u8, &combine.circuit_data)?);
            nodes.push(verifier_data(&combine.circuit_data));
            #[cfg(test)]
            eprintln!("[reward-constructor] phase=adapter-combine level={level} elapsed_ms={}", level_started.elapsed().as_millis());
        }
        let root = nodes.last().expect("reward hierarchy root").clone();
        #[cfg(test)]
        let adapter_started = std::time::Instant::now();
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let config = NetworkConfigTarget::new(&mut builder, source_chain_count);
        let session_vk = builder.constant_verifier_data(verifier);
        let (ledger_window, config_words, window_words, old_ledger_state_root) = reward_ledger_window(&mut builder, &config, &session_vk);
        builder.connect_hashes(ledger_window.start_root, old_ledger_state_root);
        let aggregate_capacity = builder.constant(F::from_canonical_usize(REWARD_PUBLICATION_CAPACITY));
        let total_count = builder.add_virtual_target();
        let segment_count = builder.add_virtual_target();
        let segment_index = builder.add_virtual_target();
        let first_ordinal = builder.add_virtual_target();
        let count = builder.add_virtual_target();
        aggregate_segment(&mut builder, REWARD_PUBLICATION_CAPACITY, total_count, segment_count, segment_index, first_ordinal, count, config.max_rewards);
        let zero = builder.zero();
        let one = builder.one();
        builder.connect(segment_index, zero);
        let publication_empty = builder.is_equal(total_count, zero);
        let expected_segments = builder.select(publication_empty, zero, one);
        builder.connect(segment_count, expected_segments);
        builder.connect(first_ordinal, zero);
        builder.connect(count, total_count);
        builder.ensure_is_less_than_or_equal(32, total_count, aggregate_capacity);
        let root_vk = builder.constant_verifier_data(&root.verifier_only);
        let root_proof = builder.add_virtual_proof_with_pis(&root.common);
        builder.verify_proof::<PoseidonGoldilocksConfig>(&root_proof, &root_vk, &root.common);
        let root_node = checked_node_prefix(&mut builder, &root_proof, REWARD_HIERARCHY_LEVELS - 1);
        let final_proof = builder.add_virtual_proof_with_pis(common);
        builder.verify_proof::<PoseidonGoldilocksConfig>(&final_proof, &session_vk, common);
        let final_state = RewardLedgerStateTargets::new(&mut builder);
        let empty = builder.is_equal(total_count, zero);
        let nonempty = builder.not(empty);
        builder.connect_hashes_if_true(nonempty, final_state.ledger_window_hash, ledger_window.hash);
        let tip_start = HashOutTarget { elements: std::array::from_fn(|index| final_proof.public_inputs[26 + index]) };
        let tip_end = HashOutTarget { elements: std::array::from_fn(|index| final_proof.public_inputs[30 + index]) };
        let tip_window = HashOutTarget { elements: std::array::from_fn(|index| final_proof.public_inputs[22 + index]) };
        builder.connect_hashes_if_true(empty, tip_start, old_ledger_state_root);
        builder.connect_hashes_if_true(empty, tip_end, old_ledger_state_root);
        builder.connect_hashes_if_true(empty, tip_window, ledger_window.hash);
        builder.connect_if_true(empty, final_proof.public_inputs[21], zero);
        builder.connect_hashes(final_state.root, tip_end);
        builder.connect_hashes(HashOutTarget { elements: std::array::from_fn(|index| final_proof.public_inputs[index]) }, ledger_window.end_checkpoint_root);
        builder.connect_if_true(nonempty, final_state.session_count, total_count);
        builder.connect_if_true(nonempty, final_state.unfinished_session_count, zero);
        builder.connect_hashes(root_node.ledger_window_hash, ledger_window.hash);
        builder.connect_hashes(root_node.new_ledger_state_root, final_state.root);
        builder.connect_hashes(root_node.ledger_final_user_root, final_state.user_root);
        builder.connect(root_node.total_count, total_count);
        builder.connect(root_node.first_ordinal, zero);
        builder.connect(root_node.count, total_count);
        let mut opening_header = config_words.to_vec();
        opening_header.extend(window_words);
        opening_header.extend(hash::word(&mut builder, ledger_window.end_checkpoint_id, 32));
        opening_header.extend(hash::encode_hash4(&mut builder, ledger_window.end_checkpoint_root.elements));
        opening_header.extend(hash::word(&mut builder, total_count, 32));
        let mut prefix = source_domain(&mut builder, b"Opening").to_vec();
        prefix.extend(opening_header);
        let mut stream = constant_stream(&mut builder, &KeccakStreamValues::default());
        for (call, length) in [(0usize, 136usize), (1, 136), (2, 16)] {
            let start = 136 * call;
            let words = std::array::from_fn(|index| prefix.get(start / 4 + index).copied().unwrap_or(zero));
            let byte_length = builder.constant(F::from_canonical_usize(length));
            stream = keccak_stream_absorb(&mut builder, stream, &words, byte_length);
        }
        connect_stream(&mut builder, &stream, &root_node.incoming);
        let opening_digest = keccak_stream_finalize(&mut builder, root_node.outgoing);
        let family = builder.constant(F::from_canonical_u8(REWARD_PUBLICATION_FAMILY));
        let header_digest = header_digest_targets(&mut builder, family, config_words, window_words, [ledger_window.end_checkpoint_id, zero],
            ledger_window.end_checkpoint_root.elements, [aggregate_capacity, total_count, segment_count, segment_index, first_ordinal, count],
            &[old_ledger_state_root.elements, tip_end.elements], opening_digest, root_node.claim_root);
        let publication = [1, 7, REWARD_PUBLICATION_FAMILY as u32, 0].map(|value| builder.constant(F::from_canonical_u32(value)));
        builder.register_public_inputs(&publication);
        builder.register_public_inputs(&opening_digest);
        builder.register_public_inputs(&root_node.claim_root);
        builder.register_public_inputs(&header_digest);
        #[cfg(test)]
        eprintln!("[reward-constructor] phase=adapter-build-entry");
        let circuit_data = builder.build::<PoseidonGoldilocksConfig>();
        #[cfg(test)]
        eprintln!("[reward-constructor] phase=adapter-build elapsed_ms={}", adapter_started.elapsed().as_millis());
        anyhow::ensure!(circuit_data.common.num_public_inputs == AGGREGATE_PI_LEN, "reward publication width mismatch");
        Ok(Self {
            circuit_data, session: VerifierCircuitData { verifier_only: verifier.clone(), common: common.clone() },
            nodes: nodes.try_into().map_err(|_| anyhow::anyhow!("reward hierarchy descriptor width mismatch"))?,
            source_chain_count, registrations: registrations.try_into().map_err(|_| anyhow::anyhow!("reward hierarchy registration width mismatch"))?,
            config, config_hash: config_words, window_id: window_words, economic_domain: ledger_window.economic_domain,
            start_root: ledger_window.start_root, end_id: ledger_window.end_checkpoint_id, end_root: ledger_window.end_checkpoint_root,
            old_ledger_state_root, aggregate_capacity, total_count, segment_count, segment_index, first_ordinal, count,
            opening_digest, claim_tree_root: root_node.claim_root, root_proof, final_proof, final_state,
        })
    }

    pub fn registrations(&self) -> &[CircuitSetRegistration] { &self.registrations }

    fn set_adapter_witness(&self, witness: &mut PartialWitness<F>, config: &NetworkConfig, opening: &SourceCheckpointRewardOpening,
        header: &InclusionAggregateHeader, tip: &RewardLedgerFinalProof<'_>, root: &ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>) -> anyhow::Result<()>
    {
        header.validate()?;
        opening.encode()?;
        anyhow::ensure!(header.family == REWARD_PUBLICATION_FAMILY, "reward publication family mismatch");
        anyhow::ensure!(header.aggregate_capacity == REWARD_PUBLICATION_CAPACITY as u32, "reward publication capacity is 1024");
        anyhow::ensure!(header.segment_index == 0 && header.first_ordinal == 0, "reward publication is one segment");
        anyhow::ensure!(header.segment_count == u32::from(header.count != 0), "reward publication segment count differs from count");
        anyhow::ensure!(header.total_count == header.count && header.total_count as usize == opening.leaves.len(), "reward publication count differs from leaves");
        anyhow::ensure!(header.total_count <= config.max_rewards && header.total_count <= REWARD_PUBLICATION_CAPACITY as u32, "reward publication exceeds 1024");
        anyhow::ensure!(header.withdrawal_roots.is_empty(), "reward publication carries withdrawal roots");
        let (Some(old_root), Some(new_root)) = (header.old_ledger_state_root, header.new_ledger_state_root) else { anyhow::bail!("reward publication ledger-state roots missing"); };
        anyhow::ensure!(header.config_hash == opening.config_hash && header.window_id == opening.window_id
            && header.end_checkpoint_id == opening.end_checkpoint_id && header.end_checkpoint_root == opening.end_checkpoint_root,
            "reward aggregate window differs from opening");
        anyhow::ensure!(config.config_hash()? == header.config_hash, "aggregate configuration mismatch");
        anyhow::ensure!(tip.proof.public_inputs.len() == REWARD_SESSION_PROOF_FIELD_COUNT, "reward tip width mismatch");
        if header.count != 0 {
            anyhow::ensure!(tip.state.session_count == header.total_count && tip.state.unfinished_session_count == 0, "reward tip does not close the window");
        } else {
            anyhow::ensure!(tip.proof.public_inputs[21] == F::ZERO && old_root == new_root, "invalid empty reward identity");
        }
        anyhow::ensure!(tip.proof.public_inputs[30..34].iter().zip(new_root).all(|(field, limb)| field.to_canonical_u64() == limb), "reward tip root differs from header");
        self.config.set_witness(witness, config)?;
        set_bytes(witness, &self.config_hash, &header.config_hash)?;
        set_bytes(witness, &self.window_id, &header.window_id)?;
        let economic_domain = config.clone().load()?.economic_domain();
        anyhow::ensure!(opening.leaves.iter().all(|leaf| leaf.economic_domain == economic_domain), "reward economic domain differs inside one publication");
        for (target, byte) in self.economic_domain.iter().zip(economic_domain) { witness.set_target(*target, F::from_canonical_u8(byte))?; }
        set_hash4(witness, self.start_root.elements, old_root)?;
        witness.set_target(self.end_id, F::from_canonical_u32(header.end_checkpoint_id as u32))?;
        set_hash4(witness, self.end_root.elements, header.end_checkpoint_root)?;
        set_hash4(witness, self.old_ledger_state_root.elements, old_root)?;
        witness.set_target(self.aggregate_capacity, F::from_canonical_u32(header.aggregate_capacity))?;
        witness.set_target(self.total_count, F::from_canonical_u32(header.total_count))?;
        witness.set_target(self.segment_count, F::from_canonical_u32(header.segment_count))?;
        witness.set_target(self.segment_index, F::from_canonical_u32(header.segment_index))?;
        witness.set_target(self.first_ordinal, F::from_canonical_u32(header.first_ordinal))?;
        witness.set_target(self.count, F::from_canonical_u32(header.count))?;
        set_bytes(witness, &self.opening_digest, &header.opening_digest)?;
        set_bytes(witness, &self.claim_tree_root, &header.claim_tree_root)?;
        witness.set_proof_with_pis_target(&self.root_proof, root)?;
        witness.set_proof_with_pis_target(&self.final_proof, tip.proof)?;
        self.final_state.set_witness(witness, tip.state)
    }

    pub fn prove(&self, config: &NetworkConfig, opening: &SourceCheckpointRewardOpening, header: &InclusionAggregateHeader,
        tip: &RewardLedgerFinalProof<'_>, leaves: &[SourceCheckpointRewardAggregateLeaf<'_>]) -> anyhow::Result<ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>>
    {
        anyhow::ensure!(leaves.len() == opening.leaves.len() && opening.leaves.iter().zip(leaves).all(|(leaf, payout)| leaf == payout.leaf), "reward opening differs from leaves");
        #[cfg(test)]
        let prove_started = std::time::Instant::now();
        #[cfg(test)]
        report_prove_phase(prove_started, "chunk-build-entry")?;
        let chunk = RewardInclusionChunkCircuit::new(&self.session.common, &self.session.verifier_only, self.source_chain_count)?;
        #[cfg(test)]
        report_prove_phase(prove_started, "chunk-build-done")?;
        anyhow::ensure!(node_registration(0, &chunk.circuit_data)? == self.registrations[0], "reward chunk descriptor changed");
        #[cfg(test)]
        report_prove_phase(prove_started, "dummy-circuit-entry")?;
        let dummy_data = dummy_circuit::<F, PoseidonGoldilocksConfig, 2>(&self.session.common);
        #[cfg(test)]
        report_prove_phase(prove_started, "dummy-circuit-done")?;
        #[cfg(test)]
        report_prove_phase(prove_started, "dummy-proof-entry")?;
        let retained_dummy_proof = dummy_proof(&dummy_data, Default::default())?;
        #[cfg(test)]
        report_prove_phase(prove_started, "dummy-proof-done")?;
        let mut inactive_slot_proof = retained_dummy_proof.clone();
        inactive_slot_proof.public_inputs = vec![F::ZERO; self.session.common.num_public_inputs];
        drop(dummy_data);
        let mut incoming = opening_prefix_stream(header)?;
        let mut proofs = Vec::with_capacity(REWARD_PUBLICATION_CAPACITY / REWARD_CHUNK_SLOTS);
        for index in 0..REWARD_PUBLICATION_CAPACITY / REWARD_CHUNK_SLOTS {
            let start = index * REWARD_CHUNK_SLOTS;
            let end = (start + REWARD_CHUNK_SLOTS).min(leaves.len());
            let slice = if start < leaves.len() { &leaves[start..end] } else { &[] };
            #[cfg(test)]
            report_prove_phase(prove_started, &format!("chunk-proof-entry index={index}"))?;
            let proof = chunk.prove(config, header, tip.state, start as u32, &incoming, slice, &retained_dummy_proof, &inactive_slot_proof)?;
            #[cfg(test)]
            report_prove_phase(prove_started, &format!("chunk-proof-done index={index}"))?;
            incoming = stream_from_proof(&proof, true)?;
            proofs.push(proof);
        }
        drop(chunk);
        drop(retained_dummy_proof);
        drop(inactive_slot_proof);
        for level in 1..REWARD_HIERARCHY_LEVELS {
            #[cfg(test)]
            report_prove_phase(prove_started, &format!("combine-build-entry level={level}"))?;
            let combine = RewardInclusionCombineCircuit::new(level, &self.nodes[level - 1])?;
            #[cfg(test)]
            report_prove_phase(prove_started, &format!("combine-build-done level={level}"))?;
            anyhow::ensure!(node_registration(level as u8, &combine.circuit_data)? == self.registrations[level], "reward combine descriptor changed");
            let mut parents = Vec::with_capacity(proofs.len() / 2);
            let mut children = proofs.into_iter();
            while let Some(left) = children.next() {
                let right = children.next().ok_or_else(|| anyhow::anyhow!("reward combine child is unpaired"))?;
                #[cfg(test)]
                let child_index = parents.len();
                #[cfg(test)]
                report_prove_phase(prove_started, &format!("combine-proof-entry level={level} index={child_index}"))?;
                let parent = combine.prove(left, right)?;
                #[cfg(test)]
                report_prove_phase(prove_started, &format!("combine-proof-done level={level} index={child_index}"))?;
                parents.push(parent);
            }
            proofs = parents;
        }
        anyhow::ensure!(proofs.len() == 1, "reward hierarchy did not reduce to one root");
        let mut witness = PartialWitness::new();
        self.set_adapter_witness(&mut witness, config, opening, header, tip, &proofs[0])?;
        #[cfg(test)]
        report_prove_phase(prove_started, "adapter-prove-entry")?;
        let proof = self.circuit_data.prove(witness)?;
        #[cfg(test)]
        report_prove_phase(prove_started, "adapter-prove-done")?;
        Ok(proof)
    }
}


fn raw_byte<const D: usize>(builder: &mut CircuitBuilder<F, D>, value: Target) -> Target
where F: Extendable<D> {
    builder.range_check(value, 8);
    value
}

fn raw_u32_bytes<const D: usize>(builder: &mut CircuitBuilder<F, D>, value: Target) -> [Target; 4]
where F: Extendable<D> {
    let bits = builder.split_le(value, 32);
    std::array::from_fn(|index| {
        let mut byte = builder.zero();
        let mut place = builder.one();
        for bit in &bits[index * 8..(index + 1) * 8] {
            byte = builder.mul_add(bit.target, place, byte);
            place = builder.add(place, place);
        }
        byte
    })
}

fn raw_u64_bytes<const D: usize>(builder: &mut CircuitBuilder<F, D>, low: Target, high: Target) -> [Target; 8]
where F: Extendable<D> {
    let low = raw_u32_bytes(builder, low);
    let high = raw_u32_bytes(builder, high);
    [high[3], high[2], high[1], high[0], low[3], low[2], low[1], low[0]]
}

fn hash4_bytes<const D: usize>(builder: &mut CircuitBuilder<F, D>, hash: [Target; 4]) -> Vec<Target>
where F: Extendable<D> {
    let mut bytes = Vec::with_capacity(32);
    for words in hash::encode_hash4(builder, hash).chunks_exact(8) {
        bytes.extend(raw_u64_bytes(builder, words[7], words[6]));
    }
    bytes
}

fn bytes32_bytes<const D: usize>(builder: &mut CircuitBuilder<F, D>, words: Bytes32Target) -> [Target; 32]
where F: Extendable<D> {
    let mut bytes = [builder.zero(); 32];
    for (index, word) in words.into_iter().enumerate() {
        let word = raw_u32_bytes(builder, word);
        bytes[index * 4] = word[3];
        bytes[index * 4 + 1] = word[2];
        bytes[index * 4 + 2] = word[1];
        bytes[index * 4 + 3] = word[0];
    }
    bytes
}

fn header_digest_targets<const D: usize>(builder: &mut CircuitBuilder<F, D>, family: Target, config_hash: Bytes32Target,
    window_id: Bytes32Target, end_id: [Target; 2], end_root: [Target; 4], scalars: [Target; 6],
    withdrawal_roots: &[[Target; 4]], opening_digest: Bytes32Target, claim_tree_root: Bytes32Target) -> Bytes32Target
where F: Extendable<D> {
    let mut bytes = Vec::with_capacity(193 + withdrawal_roots.len() * 32);
    bytes.push(raw_byte(builder, family));
    bytes.extend(bytes32_bytes(builder, config_hash));
    bytes.extend(bytes32_bytes(builder, window_id));
    bytes.extend(raw_u64_bytes(builder, end_id[0], end_id[1]));
    bytes.extend(hash4_bytes(builder, end_root));
    for scalar in scalars { bytes.extend(raw_u32_bytes(builder, scalar).into_iter().rev()); }
    for &root in withdrawal_roots { bytes.extend(hash4_bytes(builder, root)); }
    bytes.extend(bytes32_bytes(builder, opening_digest));
    bytes.extend(bytes32_bytes(builder, claim_tree_root));
    let domain = {
        let mut keccak = tiny_keccak::Keccak::v256();
        keccak.update(b"PsyBridge/TwoArtifact/1/AggregateHeader");
        let mut digest = [0u8; 32];
        keccak.finalize(&mut digest);
        hash::constant_bytes32(builder, digest)
    };
    let mut preimage = bytes32_bytes(builder, domain).to_vec();
    preimage.extend(bytes);
    let digest = keccak256_bytes_targets(builder, &preimage);
    std::array::from_fn(|index| {
        let bytes = raw_u32_bytes(builder, digest[index].0);
        let mut word = builder.zero();
        for byte in bytes {
            word = builder.mul_const(F::from_canonical_u32(256), word);
            word = builder.add(word, byte);
        }
        word
    })
}

fn claim_leaf<const D: usize>(builder: &mut CircuitBuilder<F, D>, count: Target, ordinal: Target, commit: Bytes32Target) -> Bytes32Target
where F: Extendable<D> {
    let marker = builder.constant(F::from_canonical_u8(12));
    let mut body = hash::word(builder, marker, 8).to_vec();
    body.extend(hash::word(builder, count, CLAIM_TREE_MAX_CAPACITY.ilog2() as usize + 1));
    body.extend(hash::word(builder, ordinal, CLAIM_TREE_MAX_CAPACITY.ilog2() as usize));
    body.extend(commit);
    hash::commitment(builder, Domain::Leaf, &body)
}

fn claim_empty<const D: usize>(builder: &mut CircuitBuilder<F, D>, count: Target, ordinal: Target) -> Bytes32Target
where F: Extendable<D> {
    let marker = builder.constant(F::from_canonical_u8(12));
    let mut body = hash::word(builder, marker, 8).to_vec();
    body.extend(hash::word(builder, count, CLAIM_TREE_MAX_CAPACITY.ilog2() as usize + 1));
    body.extend(hash::word(builder, ordinal, CLAIM_TREE_MAX_CAPACITY.ilog2() as usize));
    hash::commitment(builder, Domain::Empty, &body)
}

fn claim_parent<const D: usize>(builder: &mut CircuitBuilder<F, D>, level: u32, left: Bytes32Target, right: Bytes32Target) -> Bytes32Target
where F: Extendable<D> {
    let marker = builder.constant(F::from_canonical_u8(12));
    let level = builder.constant(F::from_canonical_u32(level));
    let mut body = hash::word(builder, marker, 8).to_vec();
    body.extend(hash::word(builder, level, 8));
    body.extend(left);
    body.extend(right);
    hash::commitment(builder, Domain::Node, &body)
}

fn claim_tree_root<const D: usize, const CAPACITY: usize>(builder: &mut CircuitBuilder<F, D>, commits: &[Bytes32Target; CAPACITY], count: Target) -> Bytes32Target
where F: Extendable<D> {
    let mut nodes = Vec::with_capacity(CAPACITY);
    let zero = builder.zero();
    for (ordinal, commit) in commits.iter().enumerate() {
        let position = builder.constant(F::from_canonical_usize(ordinal));
        let real = builder.is_less_than(CAPACITY.ilog2() as usize + 1, position, count);
        let inactive = builder.not(real);
        for &word in commit {
            builder.range_check(word, 32);
            builder.connect_if_true(inactive, word, zero);
        }
        let leaf = claim_leaf(builder, count, position, *commit);
        let empty = claim_empty(builder, count, position);
        nodes.push(std::array::from_fn(|index| builder.select(real, leaf[index], empty[index])));
    }
    let depth = CAPACITY.trailing_zeros();
    for level in 1..=depth {
        nodes = nodes.chunks_exact(2).map(|pair| claim_parent(builder, level, pair[0], pair[1])).collect();
    }
    nodes[0]
}

fn aggregate_segment<const D: usize>(builder: &mut CircuitBuilder<F, D>, capacity: usize, total_count: Target,
    segment_count: Target, segment_index: Target, first_ordinal: Target, count: Target, maximum_total: Target)
where F: Extendable<D> {
    builder.range_check(total_count, 32);
    builder.range_check(segment_count, 32);
    builder.range_check(segment_index, 32);
    builder.range_check(first_ordinal, 32);
    let count_bits = capacity.ilog2() as usize + 1;
    builder.range_check(count, count_bits);
    let zero = builder.zero();
    let one = builder.one();
    let capacity_target = builder.constant(F::from_canonical_usize(capacity));
    let empty = builder.is_equal(total_count, zero);
    let nonempty = builder.not(empty);
    for value in [segment_index, first_ordinal, count] { builder.connect_if_true(empty, value, zero); }
    builder.connect_if_true(empty, segment_count, zero);
    builder.ensure_is_less_than_or_equal(32, total_count, maximum_total);
    let maximum = builder.constant(F::from_canonical_usize(CLAIM_TREE_MAX_CAPACITY));
    builder.ensure_is_less_than_or_equal(32, total_count, maximum);
    let mut quotient = builder.zero();
    let mut covered = builder._false();
    let span = (CLAIM_TREE_MAX_CAPACITY as u32).div_ceil(capacity as u32);
    for candidate in 1..=span {
        let value = builder.constant(F::from_canonical_u32(candidate));
        let product = builder.mul(value, capacity_target);
        let reaches = builder.is_less_than_or_equal(32, total_count, product);
        let uncovered = builder.not(covered);
        let first = builder.and(reaches, uncovered);
        quotient = builder.select(first, value, quotient);
        covered = builder.or(covered, reaches);
    }
    builder.connect_if_true(nonempty, covered.target, one);
    builder.connect_if_true(nonempty, segment_count, quotient);
    let in_range = builder.is_less_than(32, segment_index, segment_count);
    builder.connect_if_true(nonempty, in_range.target, one);
    let first = builder.mul(segment_index, capacity_target);
    builder.connect(first_ordinal, first);
    let remaining = builder.sub(total_count, first);
    let fits = builder.is_less_than_or_equal(32, remaining, capacity_target);
    let expected_count = builder.select(fits, remaining, capacity_target);
    builder.connect_if_true(nonempty, count, expected_count);
    let count_is_zero = builder.is_equal(count, zero);
    let positive = builder.not(count_is_zero);
    builder.connect_if_true(nonempty, positive.target, one);
    builder.ensure_is_less_than_or_equal(count_bits, count, capacity_target);
}

impl<C: GenericConfig<D, F = F>, const D: usize, const CAPACITY: usize> WithdrawalInclusionAggregateCircuit<C, D, CAPACITY>
where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>> {
    /// Capacity fixes padding; NetworkConfig still limits the entire window to at most 1024 withdrawals.
    pub fn new(child: &CircuitData<F, C, D>, chain_count: usize) -> Self {
        assert!(INCLUSION_AGGREGATE_CAPACITIES.contains(&(CAPACITY as u32)));
        assert!((1..=8).contains(&chain_count));
        assert_eq!(child.common.num_public_inputs, 32);
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let zero = builder.zero();
        let one = builder.one();
        let config = NetworkConfigTarget::new(&mut builder, chain_count);
        let config_hash = config.hash(&mut builder);
        let window_id = builder.add_virtual_target_arr();
        for word in window_id { builder.range_check(word, 32); }
        let end_id = builder.add_virtual_target_arr();
        builder.range_check(end_id[0], 32);
        builder.assert_zero(end_id[1]);
        let end_root = builder.add_virtual_target_arr();
        hash::encode_hash4(&mut builder, end_root);
        let withdrawal_roots = (0..chain_count).map(|_| builder.add_virtual_target_arr::<4>()).collect::<Vec<_>>();
        for &root in &withdrawal_roots { hash::encode_hash4(&mut builder, root); }
        let chains = config.chains.iter().zip(&withdrawal_roots).map(|(chain, &root)| (chain.chain_index, root)).collect::<Vec<_>>();
        let tree_root = withdrawal_root_tree(&mut builder, &chains);
        let aggregate_capacity = builder.constant(F::from_canonical_usize(CAPACITY));
        let total_count = builder.add_virtual_target();
        let segment_count = builder.add_virtual_target();
        let segment_index = builder.add_virtual_target();
        let first_ordinal = builder.add_virtual_target();
        let count = builder.add_virtual_target();
        aggregate_segment(&mut builder, CAPACITY, total_count, segment_count, segment_index, first_ordinal, count, config.max_withdrawals);

        let dummy = dummy_circuit::<F, C, D>(&child.common);
        assert_eq!(dummy.common, child.common);
        let real_vk = builder.constant_verifier_data(&child.verifier_only);
        let dummy_vk = builder.constant_verifier_data(&dummy.verifier_only);
        let mut leaves = Vec::with_capacity(CAPACITY);
        let mut leaf_words = Vec::with_capacity(CAPACITY);
        let mut proofs = Vec::with_capacity(CAPACITY);
        let mut paths = Vec::with_capacity(CAPACITY);
        let mut commits = [hash::constant_bytes32(&mut builder, [0; 32]); CAPACITY];
        for index in 0..CAPACITY {
            let previous = leaves.last().copied().map(|leaf| match leaf { AggregateLeafTarget::Withdrawal(leaf) => leaf, _ => unreachable!() });
            let slot = constrain_aggregate_slot::<C, D>(&mut builder, index, count, zero, one, previous, child,
                &real_vk, &dummy_vk, config_hash, end_id, end_root, chain_count, tree_root, CAPACITY.ilog2() as usize + 1);
            commits[index] = slot.commit;
            leaves.push(slot.leaf);
            leaf_words.push(slot.words);
            proofs.push(slot.proof);
            paths.push(slot.path);
        }
        let mut body = config_hash.to_vec();
        body.extend(window_id);
        body.extend(hash::word_u64(&mut builder, end_id));
        body.extend(hash::encode_hash4(&mut builder, end_root));
        let chain_count_target = builder.constant(F::from_canonical_usize(chain_count));
        body.extend(hash::word(&mut builder, chain_count_target, 32));
        for &root in &withdrawal_roots { body.extend(hash::encode_hash4(&mut builder, root)); }
        body.extend(hash::word(&mut builder, count, 32));
        let opening_digest = hash::prefix_commitment(&mut builder, Domain::WithdrawalAggregate, &body, &leaf_words, count, 0);
        let claim_root = claim_tree_root::<D, CAPACITY>(&mut builder, &commits, count);
        let family = builder.constant(F::from_canonical_u8(WITHDRAWAL_PUBLICATION_FAMILY));
        let header_digest = header_digest_targets(&mut builder, family, config_hash, window_id, end_id, end_root,
            [aggregate_capacity, total_count, segment_count, segment_index, first_ordinal, count],
            &withdrawal_roots, opening_digest, claim_root);
        let prefix = [1, 7, WITHDRAWAL_PUBLICATION_FAMILY as u32, 0].map(|value| builder.constant(F::from_canonical_u32(value)));
        builder.register_public_inputs(&prefix);
        builder.register_public_inputs(&opening_digest);
        builder.register_public_inputs(&claim_root);
        builder.register_public_inputs(&header_digest);
        let circuit_data = builder.build::<C>();
        assert_eq!(circuit_data.common.num_public_inputs, AGGREGATE_PI_LEN);
        Self { circuit_data, config, config_hash, window_id, end_id, end_root, aggregate_capacity, total_count,
            segment_count, segment_index, first_ordinal, count, withdrawal_roots, opening_digest, claim_tree_root: claim_root, leaf_words, proofs, paths, dummy }
    }

    pub fn set_witness(&self, witness: &mut PartialWitness<F>, config: &NetworkConfig, window: &AggregateWindow,
        header: &InclusionAggregateHeader, leaves: &[WithdrawalAggregateLeaf<'_, C, D>]) -> anyhow::Result<()>
    {
        header.validate()?;

        anyhow::ensure!(header.total_count <= config.max_withdrawals, "withdrawal publication total exceeds network limit");
        anyhow::ensure!(header.family == WITHDRAWAL_PUBLICATION_FAMILY, "withdrawal publication family mismatch");
        anyhow::ensure!(header.aggregate_capacity as usize == CAPACITY, "withdrawal publication capacity mismatch");
        anyhow::ensure!(header.withdrawal_roots.len() == self.withdrawal_roots.len(), "withdrawal root count mismatch");
        anyhow::ensure!(header.old_ledger_state_root.is_none() && header.new_ledger_state_root.is_none(), "withdrawal publication carries nullifier roots");
        anyhow::ensure!(header.count as usize == leaves.len(), "withdrawal publication count differs from verified children");
        anyhow::ensure!(config.config_hash()? == window.config_hash && window.config_hash == header.config_hash, "aggregate configuration mismatch");
        anyhow::ensure!(window.window_id == header.window_id, "withdrawal publication window mismatch");
        anyhow::ensure!(window.end_id == header.end_checkpoint_id && window.end_root == header.end_checkpoint_root, "withdrawal publication checkpoint mismatch");
        anyhow::ensure!(window.end_id <= u32::MAX as u64, "checkpoint index exceeds tree height");
        self.config.set_witness(witness, config)?;
        set_bytes(witness, &self.config_hash, &header.config_hash)?;
        set_bytes(witness, &self.window_id, &header.window_id)?;
        witness.set_target(self.end_id[0], F::from_canonical_u32(header.end_checkpoint_id as u32))?;
        witness.set_target(self.end_id[1], F::ZERO)?;
        set_hash4(witness, self.end_root, header.end_checkpoint_root)?;
        witness.set_target(self.aggregate_capacity, F::from_canonical_u32(header.aggregate_capacity))?;
        witness.set_target(self.total_count, F::from_canonical_u32(header.total_count))?;
        witness.set_target(self.segment_count, F::from_canonical_u32(header.segment_count))?;
        witness.set_target(self.segment_index, F::from_canonical_u32(header.segment_index))?;
        witness.set_target(self.first_ordinal, F::from_canonical_u32(header.first_ordinal))?;
        witness.set_target(self.count, F::from_canonical_u32(header.count))?;
        set_bytes(witness, &self.opening_digest, &header.opening_digest)?;
        set_bytes(witness, &self.claim_tree_root, &header.claim_tree_root)?;
        for (&target, &root) in self.withdrawal_roots.iter().zip(&header.withdrawal_roots) { set_hash4(witness, target, root)?; }
        let dummy = dummy_proof(&self.dummy, Default::default())?;
        for index in 0..CAPACITY {
            if index < leaves.len() {
                set_bytes(witness, &self.leaf_words[index], &leaves[index].leaf.encode()?)?;
                witness.set_proof_with_pis_target(&self.proofs[index], leaves[index].proof)?;
                self.paths[index].set_witness(witness, Some(leaves[index].path))?;
            } else {
                for &word in &self.leaf_words[index] { witness.set_target(word, F::ZERO)?; }
                witness.set_proof_with_pis_target(&self.proofs[index], &dummy)?;
                self.paths[index].set_witness(witness, None)?;
            }
        }
        Ok(())
    }

    pub fn prove(&self, config: &NetworkConfig, window: &AggregateWindow, header: &InclusionAggregateHeader,
        leaves: &[WithdrawalAggregateLeaf<'_, C, D>]) -> anyhow::Result<ProofWithPublicInputs<F, C, D>>
    {
        let mut witness = PartialWitness::new();
        self.set_witness(&mut witness, config, window, header, leaves)?;
        self.circuit_data.prove(witness)
    }
}

pub(crate) fn set_bytes(witness: &mut PartialWitness<F>, targets: &[Target], bytes: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(bytes.len() == targets.len() * 4, "byte/target width mismatch");
    for (target, bytes) in targets.iter().zip(bytes.chunks_exact(4)) {
        witness.set_target(*target, F::from_canonical_u32(u32::from_be_bytes(bytes.try_into()?)))?;
    }
    Ok(())
}

fn set_hash4(witness: &mut PartialWitness<F>, targets: [Target; 4], value: Hash4) -> anyhow::Result<()> {
    for (target, value) in targets.into_iter().zip(value) {
        anyhow::ensure!(value < F::ORDER, "noncanonical Goldilocks root");
        witness.set_target(target, F::from_canonical_u64(value))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use psy_client_data::bridge_aggregate::ChainConfig;

    fn config(indices: &[u8]) -> NetworkConfig {
        NetworkConfig {
            version: 1, network_magic: 0, bridge_user_id: 524288, circuit_set_hash: [7; 32],
            chains: indices.iter().enumerate().map(|(ordinal, &chain_index)| ChainConfig { chain_index, chain_id: [(ordinal + 1) as u8; 32], bridge: [1; 20], state_manager: [2; 20], bootstrap_id: 0, bootstrap_root: [1, 2, 3, 4] }).collect(),
            ethereum_index: indices[0], reward_payer: [3; 20], reward_token: [4; 20], reward_per_claim: [1; 32], reward_token_decimals: 0, reward_cutover: 0, reward_end_exclusive: 100, max_deposits: 1024, max_withdrawals: 1024, max_rewards: 1024,
        }
    }

    #[test]
    fn withdrawal_lookup_rejects_wrong_row_root_ordinal_and_sibling() {
        let config = config(&[0, 3, 4, 255]);
        let roots = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]];
        let paths = withdrawal_root_paths(&config, &roots).unwrap();
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let chains = config.chains.iter().zip(roots).map(|(chain, root)| {
            (builder.constant(F::from_canonical_u8(chain.chain_index)), root.map(|value| builder.constant(F::from_canonical_u64(value))))
        }).collect::<Vec<_>>();
        let tree = withdrawal_root_tree(&mut builder, &chains);
        let active = builder.add_virtual_bool_target_safe();
        let chain = builder.add_virtual_target();
        let root = builder.add_virtual_target_arr();
        let path = WithdrawalRootTarget::build(&mut builder, active, chains.len(), chain, root, tree);
        let data = builder.build::<PoseidonGoldilocksConfig>();
        for selected in 0..4 {
            for mutation in 0..6 {
                let mut witness = PartialWitness::new();
                witness.set_bool_target(active, true).unwrap();
                witness.set_target(chain, F::from_canonical_u8(if mutation == 1 { 2 } else { config.chains[selected].chain_index })).unwrap();
                let mut supplied_root = roots[selected];
                if mutation == 2 { supplied_root[0] += 1; }
                set_hash4(&mut witness, root, supplied_root).unwrap();
                let mut supplied_path = paths[selected].clone();
                if mutation == 3 { supplied_path.ordinal = ((selected + 1) % 4) as u8; }
                if mutation == 4 { supplied_path.siblings[0][0] += 1; }
                if mutation == 5 { supplied_path.ordinal = 4; }
                path.set_witness(&mut witness, Some(&supplied_path)).unwrap();
                let result = data.prove(witness);
                if mutation == 0 { data.verify(result.unwrap()).unwrap(); }
                else { assert!(result.is_err(), "accepted lookup mutation {mutation}"); }
            }
        }
        for nonzero_padding in [false, true] {
            let mut witness = PartialWitness::new();
            witness.set_bool_target(active, false).unwrap();
            witness.set_target(chain, F::ZERO).unwrap();
            set_hash4(&mut witness, root, [0; 4]).unwrap();
            let mut padding = WithdrawalRootPath { ordinal: 0, siblings: [[0; 4]; 8] };
            if nonzero_padding { padding.siblings[7][3] = 1; }
            path.set_witness(&mut witness, Some(&padding)).unwrap();
            let result = data.prove(witness);
            if nonzero_padding { assert!(result.is_err()); }
            else { data.verify(result.unwrap()).unwrap(); }
        }
    }

    fn reward_identity_checkpoint(config: &NetworkConfig, window_id: [u8; 32]) -> (
        super::super::reward_ledger::RewardLedgerWindowValues,
        PsyCheckpointLeaf<F>,
        [[u64; 4]; 32],
        psy_client_data::qdata::checkpoint::PsyCheckpointGlobalStateRoots<F>,
    ) {
        use psy_crypto::hash::traits::qhashable::QFieldHashable;
        use plonky2::plonk::config::Hasher;
        let roots = psy_client_data::qdata::checkpoint::PsyCheckpointGlobalStateRoots::<F>::default();
        let leaf = PsyCheckpointLeaf { global_chain_root: roots.qfhash::<PoseidonHash>(), stats: Default::default() };
        let path = [[0u64; 4]; 32];
        let mut root = leaf.qfhash::<PoseidonHash>().0;
        for (height, sibling) in path.iter().enumerate() {
            let sibling = HashOut { elements: sibling.map(F::from_canonical_u64) };
            root = if (7u32 >> height) & 1 == 0 { PoseidonHash::two_to_one(root, sibling) } else { PoseidonHash::two_to_one(sibling, root) };
        }
        let window = super::super::reward_ledger::RewardLedgerWindowValues {
            config_hash: config.config_hash().unwrap(), economic_domain: config.clone().load().unwrap().economic_domain(), window_id,
            end_checkpoint_id: 7, end_checkpoint_root: root.elements.map(|value| value.to_canonical_u64()),
            start_root: psy_client_data::bridge_aggregate::origin_state_root(),
        };
        (window, leaf, path, roots)
    }

    #[test]
    fn reward_publication_proves_empty_and_rejects_digest_tampering() {
        let config = config(&[0]);
        let (window, leaf, path, roots) = reward_identity_checkpoint(&config, [5; 32]);
        eprintln!("[reward-constructor] phase=session-new-entry");
        let session = super::super::reward_session::RewardSessionCircuit::new(1, 1).unwrap();
        let started = std::time::Instant::now();
        eprintln!("[reward-constructor] phase=identity-prove-entry");
        let (proof, state) = session.prove_identity(&config, &window, &leaf, &path, &roots, None).unwrap();
        eprintln!("[reward-publication] phase=identity-tip elapsed_ms={}", started.elapsed().as_millis());
        session.circuit_data.verify(proof.clone()).unwrap();
        let common = session.circuit_data.common.clone();
        let verifier = session.circuit_data.verifier_only.clone();
        drop(session);
        let started = std::time::Instant::now();
        let aggregate = RewardInclusionAggregateCircuit::new(&common, &verifier, 1).unwrap();
        eprintln!("[reward-publication] phase=empty-publication-circuit elapsed_ms={}", started.elapsed().as_millis());
        let opening = SourceCheckpointRewardOpening { config_hash: window.config_hash, window_id: window.window_id,
            end_checkpoint_id: 7, end_checkpoint_root: window.end_checkpoint_root, leaves: Vec::new() };
        let header = InclusionAggregateHeader { family: REWARD_PUBLICATION_FAMILY, config_hash: opening.config_hash,
            window_id: opening.window_id, end_checkpoint_id: opening.end_checkpoint_id, end_checkpoint_root: opening.end_checkpoint_root,
            aggregate_capacity: 1024, total_count: 0, segment_count: 0, segment_index: 0, first_ordinal: 0, count: 0,
            withdrawal_roots: Vec::new(), old_ledger_state_root: Some(window.start_root), new_ledger_state_root: Some(window.start_root),
            opening_digest: opening.opening_digest().unwrap(),
            claim_tree_root: psy_client_data::bridge_aggregate::build_inclusion_aggregate_tree(&[], 1024).unwrap()[0] };
        let tip = RewardLedgerFinalProof { proof: &proof, state: &state };
        let started = std::time::Instant::now();
        let published = aggregate.prove(&config, &opening, &header, &tip, &[]).unwrap();
        eprintln!("[reward-publication] phase=empty-publication-prove elapsed_ms={}", started.elapsed().as_millis());
        assert_eq!(keccak_stream_finalize_values(opening_prefix_stream(&header).unwrap()).unwrap(), opening.opening_digest().unwrap());
        assert_eq!(published.public_inputs, header.publication_words().unwrap().map(F::from_canonical_u32));
        aggregate.circuit_data.verify(published).unwrap();
        let mut changed = header.clone();
        changed.opening_digest[0] ^= 1;
        assert!(aggregate.prove(&config, &opening, &changed, &tip, &[]).is_err());
        let mut changed = header.clone();
        changed.claim_tree_root[0] ^= 1;
        assert!(aggregate.prove(&config, &opening, &changed, &tip, &[]).is_err());
        let mut changed = header.clone();
        changed.new_ledger_state_root.as_mut().unwrap()[0] ^= 1;
        assert!(aggregate.prove(&config, &opening, &changed, &tip, &[]).is_err());
    }

    #[test]
    fn reward_session_identity_rejects_cross_window_predecessor_and_state_tampering() {
        let config = config(&[0]);
        let (window, leaf, path, roots) = reward_identity_checkpoint(&config, [5; 32]);
        eprintln!("[reward-constructor] phase=session-new-entry");
        let session = super::super::reward_session::RewardSessionCircuit::new(1, 1).unwrap();
        let started = std::time::Instant::now();
        eprintln!("[reward-constructor] phase=identity-prove-entry");
        let (proof, state) = session.prove_identity(&config, &window, &leaf, &path, &roots, None).unwrap();
        eprintln!("[reward-session-identity] phase=origin-proof elapsed_ms={}", started.elapsed().as_millis());
        session.circuit_data.verify(proof.clone()).unwrap();
        let mut next_window = window.clone();
        next_window.window_id[0] ^= 1;
        let started = std::time::Instant::now();
        eprintln!("[reward-constructor] phase=identity-prove-entry");
        let (next, next_state) = session.prove_identity(&config, &next_window, &leaf, &path, &roots, Some((&proof, &state))).unwrap();
        eprintln!("[reward-session-identity] phase=cross-window-proof elapsed_ms={}", started.elapsed().as_millis());
        session.circuit_data.verify(next.clone()).unwrap();
        assert_eq!(next_state, state);
        assert_eq!(next.public_inputs[26..34], proof.public_inputs[26..34]);
        assert_ne!(next.public_inputs[22..26], proof.public_inputs[22..26]);
        let common = session.circuit_data.common.clone();
        let verifier = session.circuit_data.verifier_only.clone();
        drop(session);
        let started = std::time::Instant::now();
        let aggregate = RewardInclusionAggregateCircuit::new(&common, &verifier, 1).unwrap();
        eprintln!("[reward-session-identity] phase=cross-window-publication-circuit elapsed_ms={}", started.elapsed().as_millis());
        let opening = SourceCheckpointRewardOpening { config_hash: window.config_hash, window_id: window.window_id,
            end_checkpoint_id: 7, end_checkpoint_root: window.end_checkpoint_root, leaves: Vec::new() };
        let header = InclusionAggregateHeader { family: REWARD_PUBLICATION_FAMILY, config_hash: opening.config_hash,
            window_id: opening.window_id, end_checkpoint_id: opening.end_checkpoint_id, end_checkpoint_root: opening.end_checkpoint_root,
            aggregate_capacity: 1024, total_count: 0, segment_count: 0, segment_index: 0, first_ordinal: 0, count: 0,
            withdrawal_roots: Vec::new(), old_ledger_state_root: Some(window.start_root), new_ledger_state_root: Some(window.start_root),
            opening_digest: opening.opening_digest().unwrap(),
            claim_tree_root: psy_client_data::bridge_aggregate::build_inclusion_aggregate_tree(&[], 1024).unwrap()[0] };
        let mut next_opening = opening;
        next_opening.window_id = next_window.window_id;
        let mut next_header = header;
        next_header.window_id = next_window.window_id;
        next_header.opening_digest = next_opening.opening_digest().unwrap();
        let started = std::time::Instant::now();
        let published = aggregate.prove(&config, &next_opening, &next_header,
            &RewardLedgerFinalProof { proof: &next, state: &next_state }, &[]).unwrap();
        eprintln!("[reward-session-identity] phase=cross-window-publication-prove elapsed_ms={}", started.elapsed().as_millis());
        assert_eq!(published.public_inputs, next_header.publication_words().unwrap().map(F::from_canonical_u32));
        aggregate.circuit_data.verify(published).unwrap();
        drop(aggregate);
        eprintln!("[reward-constructor] phase=tamper-session-new-entry");
        let session = super::super::reward_session::RewardSessionCircuit::new(1, 1).unwrap();
        let started = std::time::Instant::now();
        let mut invalid_predecessor = proof.clone();
        invalid_predecessor.public_inputs[30] += F::ONE;
        eprintln!("[reward-constructor] phase=identity-prove-entry");
        assert!(session.prove_identity(&config, &next_window, &leaf, &path, &roots, Some((&invalid_predecessor, &state))).is_err());
        let mut invalid_state = state;
        invalid_state.session_count += 1;
        eprintln!("[reward-constructor] phase=identity-prove-entry");
        assert!(session.prove_identity(&config, &next_window, &leaf, &path, &roots, Some((&proof, &invalid_state))).is_err());
        eprintln!("[reward-session-identity] phase=tamper-rejection elapsed_ms={}", started.elapsed().as_millis());
        drop(session);
    }
    #[test]
    fn reward_hierarchy_rejects_inactive_encoding_dummy_and_stream_mutations() {
        use psy_crypto::hash::traits::qhashable::QFieldHashable;
        let config = config(&[0]);
        eprintln!("[reward-constructor] phase=session-new-entry");
        let session = super::super::reward_session::RewardSessionCircuit::new(1, 1).unwrap();
        let roots = psy_client_data::qdata::checkpoint::PsyCheckpointGlobalStateRoots::<F>::default();
        let leaf = PsyCheckpointLeaf { global_chain_root: roots.qfhash::<PoseidonHash>(), stats: Default::default() };
        let path = [[0u64; 4]; 32];
        let mut root = leaf.qfhash::<PoseidonHash>().0;
        for (height, sibling) in path.iter().enumerate() {
            let sibling = HashOut { elements: sibling.map(F::from_canonical_u64) };
            root = if (7u32 >> height) & 1 == 0 { PoseidonHash::two_to_one(root, sibling) } else { PoseidonHash::two_to_one(sibling, root) };
        }
        let window = super::super::reward_ledger::RewardLedgerWindowValues {
            config_hash: config.config_hash().unwrap(), economic_domain: config.clone().load().unwrap().economic_domain(), window_id: [5; 32],
            end_checkpoint_id: 7, end_checkpoint_root: root.elements.map(|value| value.to_canonical_u64()),
            start_root: psy_client_data::bridge_aggregate::origin_state_root(),
        };
        eprintln!("[reward-constructor] phase=identity-prove-entry");
        let (proof, state) = session.prove_identity(&config, &window, &leaf, &path, &roots, None).unwrap();
        let common = session.circuit_data.common.clone();
        let verifier = session.circuit_data.verifier_only.clone();
        drop(session);
        let opening = SourceCheckpointRewardOpening { config_hash: window.config_hash, window_id: window.window_id,
            end_checkpoint_id: 7, end_checkpoint_root: window.end_checkpoint_root, leaves: Vec::new() };
        let header = InclusionAggregateHeader { family: REWARD_PUBLICATION_FAMILY, config_hash: opening.config_hash,
            window_id: opening.window_id, end_checkpoint_id: opening.end_checkpoint_id, end_checkpoint_root: opening.end_checkpoint_root,
            aggregate_capacity: 1024, total_count: 0, segment_count: 0, segment_index: 0, first_ordinal: 0, count: 0,
            withdrawal_roots: Vec::new(), old_ledger_state_root: Some(window.start_root), new_ledger_state_root: Some(window.start_root),
            opening_digest: opening.opening_digest().unwrap(),
            claim_tree_root: psy_client_data::bridge_aggregate::build_inclusion_aggregate_tree(&[], 1024).unwrap()[0] };
        let chunk = RewardInclusionChunkCircuit::new(&common, &verifier, 1).unwrap();
        let dummy_data = dummy_circuit::<F, PoseidonGoldilocksConfig, 2>(&common);
        let retained = dummy_proof(&dummy_data, Default::default()).unwrap();
        drop(dummy_data);
        let mut inactive = retained.clone();
        inactive.public_inputs.fill(F::ZERO);
        let incoming = opening_prefix_stream(&header).unwrap();
        let mut shifted = incoming;
        shifted.state[3][1] ^= 0x0100_0000;
        let proved = chunk.prove(&config, &header, &state, 0, &shifted, &[], &retained, &inactive).unwrap();
        chunk.circuit_data.verify(proved.clone()).unwrap();
        assert!(proved.public_inputs[19].is_zero() && proved.public_inputs[20].is_zero(), "empty chunk boundary users are nonzero");
        let base = |incoming: &KeccakStreamValues| {
            let mut witness = PartialWitness::new();
            chunk.config.set_witness(&mut witness, &config).unwrap();
            set_bytes(&mut witness, &chunk.config_hash, &header.config_hash).unwrap();
            set_bytes(&mut witness, &chunk.window_id, &header.window_id).unwrap();
            for (target, byte) in chunk.economic_domain.iter().zip(window.economic_domain) { witness.set_target(*target, F::from_canonical_u8(byte)).unwrap(); }
            set_hash4(&mut witness, chunk.start_root.elements, window.start_root).unwrap();
            witness.set_target(chunk.end_id, F::from_canonical_u32(header.end_checkpoint_id as u32)).unwrap();
            set_hash4(&mut witness, chunk.end_root.elements, header.end_checkpoint_root).unwrap();
            set_hash4(&mut witness, chunk.old_ledger_state_root.elements, window.start_root).unwrap();
            chunk.final_state.set_witness(&mut witness, &state).unwrap();
            witness.set_target(chunk.total_count, F::ZERO).unwrap();
            witness.set_target(chunk.first_ordinal, F::ZERO).unwrap();
            set_stream(&mut witness, &chunk.incoming, incoming).unwrap();
            witness.set_proof_with_pis_target(&chunk.dummy_proof, &retained).unwrap();
            let empty_leaf = PsyCheckpointLeaf::default();
            let zero_state = RewardLedgerStateValues { ledger_window_hash: [0; 4], ledger_root: [0; 4], user_root: [0; 4], session_count: 0, unfinished_session_count: 0 };
            for slot in &chunk.slots {
                set_bytes(&mut witness, &slot.leaf_words, &[0u8; SOURCE_CHECKPOINT_REWARD_LEAF_BYTES]).unwrap();
                witness.set_proof_with_pis_target(&slot.proof, &inactive).unwrap();
                slot.state.set_witness(&mut witness, &zero_state).unwrap();
                witness.set_target(slot.source_checkpoint_id, F::ZERO).unwrap();
                slot.source.checkpoint_leaf.set_witness(&mut witness, &empty_leaf).unwrap();
                for sibling in slot.source.path.siblings.iter().chain(&slot.summary_siblings) { set_hash4(&mut witness, sibling.elements, [0; 4]).unwrap(); }
                set_hash4(&mut witness, slot.session_root.elements, [0; 4]).unwrap();
            }
            witness
        };
        let accepted = chunk.circuit_data.prove(base(&shifted)).unwrap();
        chunk.circuit_data.verify(accepted).unwrap();
        let mut inactive_word = base(&shifted);
        inactive_word.target_values.insert(chunk.slots[0].leaf_words[0], F::ONE);
        assert!(chunk.circuit_data.prove(inactive_word).is_err(), "accepted a nonzero inactive payout word");
        for changed in [KeccakStreamValues { byte_offset: 41, ..shifted }, {
            let mut changed = shifted;
            changed.state[0][0] ^= 1;
            changed
        }] {
            let accepted = chunk.circuit_data.prove(base(&changed)).unwrap();
            let outgoing = stream_from_proof(&accepted, true).unwrap();
            assert_eq!(outgoing.state, changed.state);
            assert_eq!(outgoing.byte_offset, changed.byte_offset);
            chunk.circuit_data.verify(accepted).unwrap();
        }
        let mut bad_ordinal = base(&shifted);
        bad_ordinal.target_values.insert(chunk.first_ordinal, F::ONE);
        assert!(chunk.circuit_data.prove(bad_ordinal).is_err(), "accepted an unaligned chunk ordinal");
        let mut bad_count = base(&shifted);
        bad_count.target_values.insert(chunk.total_count, F::from_canonical_u32(1025));
        assert!(chunk.circuit_data.prove(bad_count).is_err(), "accepted a count above 1024");
        let mut dummy_assignment = PartialWitness::new();
        dummy_assignment.set_proof_with_pis_target(&chunk.dummy_proof, &retained).unwrap();
        let mut omitted_dummy = base(&shifted);
        for target in dummy_assignment.target_values.keys() { omitted_dummy.target_values.remove(target); }
        assert!(chunk.circuit_data.prove(omitted_dummy).is_err(), "accepted an unassigned shared dummy proof");
        let mut corrupt_dummy = base(&shifted);
        corrupt_dummy.target_values.insert(chunk.dummy_proof.public_inputs[0], retained.public_inputs[0] + F::ONE);
        assert!(chunk.circuit_data.prove(corrupt_dummy).is_err(), "accepted a corrupted shared dummy proof");
        let combine = RewardInclusionCombineCircuit::new(1, &verifier_data(&chunk.circuit_data)).unwrap();
        let right = chunk.prove(&config, &header, &state, REWARD_CHUNK_SLOTS as u32, &shifted, &[], &retained, &inactive).unwrap();
        let parent = combine.prove(proved.clone(), right).unwrap();
        combine.circuit_data.verify(parent).unwrap();
        let right = chunk.prove(&config, &header, &state, REWARD_CHUNK_SLOTS as u32, &incoming, &[], &retained, &inactive).unwrap();
        chunk.circuit_data.verify(right.clone()).unwrap();
        assert!(combine.prove(proved, right).is_err(), "accepted disconnected genuine child streams");
        drop(combine);
        drop(chunk);
        let aggregate = RewardInclusionAggregateCircuit::new(&common, &verifier, 1).unwrap();
        for (stream, accepted) in [(incoming, true), (shifted, false)] {
            let chunk = RewardInclusionChunkCircuit::new(&common, &verifier, 1).unwrap();
            let mut proofs = (0..REWARD_PUBLICATION_CAPACITY / REWARD_CHUNK_SLOTS).map(|index| chunk.prove(&config, &header, &state, (index * REWARD_CHUNK_SLOTS) as u32,
                &stream, &[], &retained, &inactive).unwrap()).collect::<Vec<_>>();
            drop(chunk);
            for level in 1..REWARD_HIERARCHY_LEVELS {
                let combine = RewardInclusionCombineCircuit::new(level, &aggregate.nodes[level - 1]).unwrap();
                let mut parents = Vec::with_capacity(proofs.len() / 2);
                let mut children = proofs.into_iter();
                while let Some(left) = children.next() { parents.push(combine.prove(left, children.next().unwrap()).unwrap()); }
                drop(combine);
                proofs = parents;
            }
            let root = proofs.pop().unwrap();
            aggregate.nodes[REWARD_HIERARCHY_LEVELS - 1].verify(root.clone()).unwrap();
            let mut adapter = PartialWitness::new();
            aggregate.set_adapter_witness(&mut adapter, &config, &opening, &header,
                &RewardLedgerFinalProof { proof: &proof, state: &state }, &root).unwrap();
            let result = aggregate.circuit_data.prove(adapter);
            if accepted {
                let published = result.unwrap();
                assert_eq!(published.public_inputs, header.publication_words().unwrap().map(F::from_canonical_u32));
                aggregate.circuit_data.verify(published).unwrap();
            } else { assert!(result.is_err(), "accepted a genuine level-8 root with a mutated prefix stream"); }
        }
    }

    #[test]
    fn reward_amount_words_reverse_native_little_endian_limbs() {
        let leaf = SourceCheckpointRewardLeaf { economic_domain: [6; 32], source_checkpoint_id: 7,
            user_id: 9, amount: [1, 2, 3, 4, 5, 6, 7, 8], recipient: [9; 20], initialized: true };
        let encoded = leaf.encode().unwrap();
        assert_eq!(&encoded[96..100], &8u32.to_be_bytes());
        assert_eq!(&encoded[124..128], &1u32.to_be_bytes());
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let amount = leaf.amount.map(|value| builder.constant(F::from_canonical_u32(value)));
        let mut words = hash::constant_bytes32(&mut builder, leaf.economic_domain).to_vec();
        let source = builder.constant(F::from_canonical_u64(leaf.source_checkpoint_id));
        words.extend(hash::word(&mut builder, source, 32));
        let user = builder.constant(F::from_canonical_u32(leaf.user_id));
        words.extend(hash::word(&mut builder, user, 32));
        words.extend(amount_words(&mut builder, &amount));
        let recipient = std::array::from_fn(|i| builder.constant(F::from_canonical_u32(
            u32::from_be_bytes(leaf.recipient[i * 4..i * 4 + 4].try_into().unwrap()))));
        words.extend(hash::word_address(&mut builder, recipient));
        let one = builder.one();
        words.extend(hash::word(&mut builder, one, 1));
        let commit = source_checkpoint_reward_leaf_commit(&mut builder, &words);
        builder.register_public_inputs(&words);
        builder.register_public_inputs(&commit);
        let opening = SourceCheckpointRewardOpening { config_hash: [7; 32], window_id: [5; 32],
            end_checkpoint_id: 7, end_checkpoint_root: [1, 2, 3, 4], leaves: vec![leaf.clone()] };
        let mut prefix = source_domain(&mut builder, b"Opening").to_vec();
        prefix.extend(hash::constant_bytes32(&mut builder, opening.config_hash));
        prefix.extend(hash::constant_bytes32(&mut builder, opening.window_id));
        prefix.extend(hash::word(&mut builder, source, 32));
        let root = opening.end_checkpoint_root.map(|value| builder.constant(F::from_canonical_u64(value)));
        prefix.extend(hash::encode_hash4(&mut builder, root));
        prefix.extend(hash::word(&mut builder, one, 32));
        prefix.extend(words);
        let zero = builder.zero();
        let mut stream = constant_stream(&mut builder, &KeccakStreamValues::default());
        for part in prefix.chunks(34) {
            let input = std::array::from_fn(|i| part.get(i).copied().unwrap_or(zero));
            let length = builder.constant(F::from_canonical_usize(part.len() * 4));
            stream = keccak_stream_absorb(&mut builder, stream, &input, length);
        }
        let digest = keccak_stream_finalize(&mut builder, stream);
        builder.register_public_inputs(&digest);
        let data = builder.build::<PoseidonGoldilocksConfig>();
        let proof = data.prove(PartialWitness::new()).unwrap();
        let expected = encoded.into_iter().chain(leaf.leaf_commit().unwrap()).chain(opening.opening_digest().unwrap()).collect::<Vec<_>>();
        assert_eq!(proof.public_inputs, expected.chunks_exact(4).map(|word|
            F::from_canonical_u32(u32::from_be_bytes(word.try_into().unwrap()))).collect::<Vec<_>>());
        data.verify(proof).unwrap();
    }

    #[test]
    fn reward_registrations_are_sorted_hierarchy_descriptors() {
        eprintln!("[reward-constructor] phase=session-new-entry");
        let session = super::super::reward_session::RewardSessionCircuit::new(1, 1).unwrap();
        let common = session.circuit_data.common.clone();
        let verifier = session.circuit_data.verifier_only.clone();
        drop(session);
        let aggregate = RewardInclusionAggregateCircuit::new(&common, &verifier, 1).unwrap();
        let registrations = aggregate.registrations().to_vec();
        assert_eq!(registrations.len(), REWARD_HIERARCHY_LEVELS);
        assert_eq!(aggregate.circuit_data.common.num_public_inputs, AGGREGATE_PI_LEN);
        for (level, registration) in registrations.iter().enumerate() {
            assert_eq!((registration.family, registration.level, registration.variant, registration.pi_words),
                (REWARD_AGGREGATE_NODE_FAMILY as u16, level as u8, REWARD_AGGREGATE_NODE_VARIANT, REWARD_AGGREGATE_NODE_PI_LEN as u16));
            assert_ne!(registration.fingerprint, [0; 4]);
            assert_eq!(registration.identity_fingerprint, [0; 4]);
        }
        drop(aggregate);
        let rebuilt = RewardInclusionAggregateCircuit::new(&common, &verifier, 1).unwrap();
        assert_eq!(rebuilt.registrations(), registrations.as_slice());
    }
    #[test]
    fn active_source_path_rejects_sibling_mutation_and_inactive_zero_stands() {
        use psy_common_circuit::traits::ToTargets;
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let active = builder.add_virtual_bool_target_safe();
        let source_id = builder.add_virtual_target();
        let end_checkpoint = builder.add_virtual_target();
        let publication_root = builder.add_virtual_hash();
        let zero = builder.zero();
        let source_index = builder.select(active, source_id, zero);
        let leaf = PsyCheckpointLeafGadget::create_virtual(&mut builder);
        let inactive = builder.not(active);
        for target in leaf.to_targets() { builder.connect_if_true(inactive, target, zero); }
        let computed_root = builder.add_virtual_hash();
        let source = historical_merkle_proof(&mut builder, [source_index, zero], &leaf, [end_checkpoint, zero], computed_root);
        builder.connect_hashes_if_true(active, source.path.root, publication_root);
        for sibling in &source.path.siblings { for target in sibling.elements { builder.connect_if_true(inactive, target, zero); } }
        builder.register_public_inputs(&computed_root.elements);
        let data = builder.build::<PoseidonGoldilocksConfig>();
        let mut discovered = PartialWitness::new();
        discovered.set_bool_target(active, true).unwrap();
        discovered.set_target(source_id, F::ONE).unwrap();
        discovered.set_target(end_checkpoint, F::from_canonical_u32(3)).unwrap();
        for target in leaf.to_targets() { discovered.set_target(target, F::ZERO).unwrap(); }
        for sibling in &source.path.siblings { discovered.set_hash_target(*sibling, HashOut { elements: [F::ZERO; 4] }).unwrap(); }
        let accepted = data.prove(discovered).unwrap();
        data.verify(accepted.clone()).unwrap();
        let root = HashOut { elements: [accepted.public_inputs[0], accepted.public_inputs[1], accepted.public_inputs[2], accepted.public_inputs[3]] };
        let assign = |active_value: bool, sibling: F| {
            let mut witness = PartialWitness::new();
            witness.set_bool_target(active, active_value).unwrap();
            witness.set_target(source_id, if active_value { F::ONE } else { F::ZERO }).unwrap();
            witness.set_target(end_checkpoint, F::from_canonical_u32(3)).unwrap();
            witness.set_hash_target(publication_root, root).unwrap();
            for target in leaf.to_targets() { witness.set_target(target, F::ZERO).unwrap(); }
            for (index, target) in source.path.siblings.iter().enumerate() {
                let value = if active_value && index == 0 { sibling } else { F::ZERO };
                witness.set_hash_target(*target, HashOut { elements: [value; 4] }).unwrap();
            }
            witness
        };
        let inactive_proof = data.prove(assign(false, F::ZERO)).unwrap();
        data.verify(inactive_proof).unwrap();
        assert!(data.prove(assign(true, F::ONE)).is_err(), "accepted active source sibling mutation");
    }
    #[test]
    fn aggregate_segment_capacity_boundaries_and_network_total() {
        for capacity in INCLUSION_AGGREGATE_CAPACITIES {
            let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
            let values = builder.add_virtual_target_arr::<6>();
            let [total, segments, index, first, count, maximum] = values;
            aggregate_segment(&mut builder, capacity as usize, total, segments, index, first, count, maximum);
            let position = builder.constant(F::from_canonical_u32(capacity - 1));
            let active = builder.is_less_than(capacity.ilog2() as usize + 1, position, count);
            builder.register_public_input(active.target);
            let data = builder.build::<PoseidonGoldilocksConfig>();
            for (assignment, accepted, last_active) in [
                ([capacity, 1, 0, 0, capacity, capacity], true, true),
                ([capacity - 1, 1, 0, 0, capacity - 1, capacity], true, false),
                ([capacity, 1, 0, 0, capacity - 1, capacity], false, false),
                ([capacity, 1, 1, capacity, capacity, capacity], false, false),
                ([2048, 2048u32.div_ceil(capacity), 0, 0, 2048u32.min(capacity), 1024], false, false),
            ] {
                let mut witness = PartialWitness::new();
                for (target, value) in values.into_iter().zip(assignment) { witness.set_target(target, F::from_canonical_u32(value)).unwrap(); }
                let result = data.prove(witness);
                if accepted {
                    let proof = result.unwrap();
                    assert_eq!(proof.public_inputs, [F::from_bool(last_active)]);
                    data.verify(proof).unwrap();
                } else { assert!(result.is_err(), "accepted segment {assignment:?} at capacity {capacity}"); }
            }
        }
    }

    #[test]
    fn header_hash4_bytes_reject_noncanonical_field_decomposition() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let root = builder.add_virtual_target_arr();
        let bytes = hash4_bytes(&mut builder, root);
        builder.register_public_inputs(&bytes);
        let data = builder.build::<PoseidonGoldilocksConfig>();
        let canonical = [0, F::ORDER - 1, 0x0102030405060708, 9];
        let mut witness = PartialWitness::new();
        set_hash4(&mut witness, root, canonical).unwrap();
        let proof = data.prove(witness).unwrap();
        let expected = canonical.into_iter().flat_map(u64::to_be_bytes).map(F::from_canonical_u8).collect::<Vec<_>>();
        assert_eq!(proof.public_inputs, expected);
        data.verify(proof).unwrap();
        let mut witness = PartialWitness::new();
        set_hash4(&mut witness, root, canonical).unwrap();
        for (target, byte) in bytes[..8].iter().zip(F::ORDER.to_be_bytes()) {
            witness.set_target(*target, F::from_canonical_u8(byte)).unwrap();
        }
        assert!(data.prove(witness).is_err(), "accepted modulus bytes as field zero");
    }

    #[test]
    fn packed_header_digest_matches_native_asymmetric_bytes() {
        let header = InclusionAggregateHeader {
            family: WITHDRAWAL_PUBLICATION_FAMILY, config_hash: std::array::from_fn(|i| i as u8),
            window_id: std::array::from_fn(|i| (255 - i) as u8), end_checkpoint_id: 0x01020304,
            end_checkpoint_root: [0, F::ORDER - 1, 0x0102030405060708, 9], aggregate_capacity: 1024,
            total_count: 2051, segment_count: 3, segment_index: 2, first_ordinal: 2048, count: 3,
            withdrawal_roots: vec![[0x1020304050607080, 2, 3, 4]], old_ledger_state_root: None, new_ledger_state_root: None,
            opening_digest: std::array::from_fn(|i| (i * 7) as u8), claim_tree_root: std::array::from_fn(|i| (i * 3) as u8),
        };
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let family = builder.constant(F::from_canonical_u8(header.family));
        let config_hash = hash::constant_bytes32(&mut builder, header.config_hash);
        let window_id = hash::constant_bytes32(&mut builder, header.window_id);
        let end_id = [builder.constant(F::from_canonical_u64(header.end_checkpoint_id)), builder.zero()];
        let end_root = header.end_checkpoint_root.map(|value| builder.constant(F::from_canonical_u64(value)));
        let scalars = [header.aggregate_capacity, header.total_count, header.segment_count, header.segment_index, header.first_ordinal, header.count]
            .map(|value| builder.constant(F::from_canonical_u32(value)));
        let roots = header.withdrawal_roots.iter().map(|root| root.map(|value| builder.constant(F::from_canonical_u64(value)))).collect::<Vec<_>>();
        let opening = hash::constant_bytes32(&mut builder, header.opening_digest);
        let claim = hash::constant_bytes32(&mut builder, header.claim_tree_root);
        let digest = header_digest_targets(&mut builder, family, config_hash, window_id, end_id, end_root, scalars, &roots, opening, claim);
        builder.register_public_inputs(&digest);
        let data = builder.build::<PoseidonGoldilocksConfig>();
        let proof = data.prove(PartialWitness::new()).unwrap();
        let expected = header.header_digest().unwrap().chunks_exact(4).map(|bytes| F::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap()))).collect::<Vec<_>>();
        assert_eq!(proof.public_inputs, expected);
        data.verify(proof).unwrap();
    }

    fn withdrawal_child(config: &NetworkConfig, window: &AggregateWindow, leaf: &WithdrawalLeaf, root: Hash4) -> (CircuitData<F, PoseidonGoldilocksConfig, 2>, ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>) {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let targets = builder.add_virtual_targets(32);
        builder.register_public_inputs(&targets);
        let child = builder.build::<PoseidonGoldilocksConfig>();
        let mut witness = PartialWitness::new();
        for (target, value) in targets[..4].iter().zip([1u32, 2, 0, 0]) { witness.set_target(*target, F::from_canonical_u32(value)).unwrap(); }
        set_bytes(&mut witness, &targets[4..12], &config.config_hash().unwrap()).unwrap();
        witness.set_target(targets[12], F::from_canonical_u32(window.end_id as u32)).unwrap();
        witness.set_target(targets[13], F::ZERO).unwrap();
        set_hash4(&mut witness, targets[14..18].try_into().unwrap(), window.end_root).unwrap();
        witness.set_target(targets[18], F::from_canonical_u32(BRIDGE_USER_ID)).unwrap();
        witness.set_target(targets[19], F::from_canonical_u8(leaf.chain_index)).unwrap();
        set_hash4(&mut witness, targets[20..24].try_into().unwrap(), root).unwrap();
        set_bytes(&mut witness, &targets[24..32], &leaf.leaf_commit().unwrap()).unwrap();
        let proof = child.prove(witness).unwrap();
        (child, proof)
    }

    fn publication(config: &NetworkConfig, window: &AggregateWindow, roots: &[Hash4], leaves: &[WithdrawalLeaf], count: u32, total: u32) -> InclusionAggregateHeader {
        let opening = psy_client_data::bridge_aggregate::WithdrawalAggregateOpening {
            config_hash: window.config_hash, window_id: window.window_id, end_checkpoint_id: window.end_id,
            end_checkpoint_root: window.end_root, withdrawal_roots: roots.to_vec(), withdrawals: leaves[..count as usize].to_vec(),
        };
        let mut header = InclusionAggregateHeader {
            family: WITHDRAWAL_PUBLICATION_FAMILY, config_hash: window.config_hash, window_id: window.window_id,
            end_checkpoint_id: window.end_id, end_checkpoint_root: window.end_root, aggregate_capacity: 1024,
            total_count: total, segment_count: if total == 0 { 0 } else { 1 }, segment_index: 0, first_ordinal: 0, count,
            withdrawal_roots: roots.to_vec(), old_ledger_state_root: None, new_ledger_state_root: None,
            opening_digest: opening.opening_digest(config).unwrap(), claim_tree_root: [0; 32],
        };
        let commits = leaves[..count as usize].iter().map(|leaf| leaf.leaf_commit().unwrap()).collect::<Vec<_>>();
        psy_client_data::bridge_aggregate::bind_claim_tree(&mut header, &commits).unwrap();
        header.validate().unwrap();
        header
    }

    #[test]
    fn withdrawal_publication_binds_header_digests_and_rejects_segment_mutations() {
        let config = config(&[0]);
        let window = AggregateWindow { config_hash: config.config_hash().unwrap(), window_id: [5; 32], end_id: 7, end_root: [1, 2, 3, 4] };
        let roots = [[9, 8, 7, 6]];
        let paths = withdrawal_root_paths(&config, &roots).unwrap();
        let leaves = (0..2).map(|index| WithdrawalLeaf { chain_index: 0, sender_user_id: 11, recipient: [1; 20], token: [2; 20], amount: [3; 32], nonce: { let mut nonce = [4; 32]; nonce[31] = index; nonce } }).collect::<Vec<_>>();
        let (child, first) = withdrawal_child(&config, &window, &leaves[0], roots[0]);
        let (_, second) = withdrawal_child(&config, &window, &leaves[1], roots[0]);
        let proofs = [first, second];
        let aggregate = WithdrawalInclusionAggregateCircuit::<_, 2, 1024>::new(&child, 1);
        assert_eq!(aggregate.circuit_data.common.num_public_inputs, AGGREGATE_PI_LEN);
        let records = leaves.iter().zip(&proofs).map(|(leaf, proof)| WithdrawalAggregateLeaf { leaf, proof, path: &paths[0] }).collect::<Vec<_>>();
        let header = publication(&config, &window, &roots, &leaves, 1, 1);
        let proof = aggregate.prove(&config, &window, &header, &records[..1]).unwrap();
        let words = header.publication_words().unwrap();
        assert_eq!(proof.public_inputs, words.map(F::from_canonical_u32));
        aggregate.circuit_data.verify(proof).unwrap();
        let empty = publication(&config, &window, &roots, &leaves, 0, 0);
        assert_ne!(empty.opening_digest, [0; 32]);
        assert_ne!(empty.claim_tree_root, [0; 32]);
        let empty_proof = aggregate.prove(&config, &window, &empty, &[]).unwrap();
        assert_eq!(empty_proof.public_inputs, empty.publication_words().unwrap().map(F::from_canonical_u32));
        aggregate.circuit_data.verify(empty_proof).unwrap();
        let mut wrong_opening = empty.clone();
        wrong_opening.opening_digest[0] ^= 1;
        assert!(aggregate.prove(&config, &window, &wrong_opening, &[]).is_err());
        let mut wrong_claim = empty.clone();
        wrong_claim.claim_tree_root[0] ^= 1;
        assert!(aggregate.prove(&config, &window, &wrong_claim, &[]).is_err());
        for mutation in 0..8u8 {
            let mut changed = header.clone();
            match mutation {
                0 => changed.segment_index = 1,
                1 => changed.total_count = 1025,
                2 => changed.first_ordinal = 1,
                3 => changed.count = 2,
                4 => changed.claim_tree_root[0] ^= 1,
                5 => changed.opening_digest[0] ^= 1,
                6 => changed.withdrawal_roots[0][0] += 1,
                _ => changed.aggregate_capacity = 2048,
            }
            assert!(aggregate.prove(&config, &window, &changed, &records[..1]).is_err(), "accepted publication mutation {mutation}");
        }
        for mutation in 0..9 {
            let mut witness = PartialWitness::new();
            aggregate.set_witness(&mut witness, &config, &window, &header, &records[..1]).unwrap();
            match mutation {
                0 => { witness.target_values.insert(aggregate.proofs[0].public_inputs[24], F::ZERO); }
                1 => { witness.target_values.insert(aggregate.leaf_words[1][7], F::ONE); }
                2 => { witness.target_values.insert(aggregate.proofs[1].public_inputs[0], F::ONE); }
                3 => { witness.target_values.insert(aggregate.paths[1].siblings[7].elements[3], F::ONE); }
                4 => { witness.target_values.insert(aggregate.segment_index, F::ONE); }
                5 => { witness.target_values.insert(aggregate.first_ordinal, F::ONE); }
                6 => { witness.target_values.insert(aggregate.count, F::ZERO); }
                7 => { witness.target_values.insert(aggregate.opening_digest[0], F::ZERO); }
                _ => { witness.target_values.insert(aggregate.claim_tree_root[0], F::ZERO); }
            }
            assert!(aggregate.circuit_data.prove(witness).is_err(), "accepted withdrawal witness mutation {mutation}");
        }
    }
}
