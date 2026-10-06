use parth_core::crypto::hash::traits::MerkleZeroHasher;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::{Field, Field64, PrimeField64}},
    hash::{hash_types::{HashOut, HashOutTarget}, poseidon::PoseidonHash},
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData}, config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}},
    recursion::dummy_circuit::{dummy_circuit, dummy_proof},
};
use psy_client_data::bridge_aggregate::{Bytes32, Hash4, InclusionAggregateHeader, NetworkConfig, SourceCheckpointRewardLeaf, SourceCheckpointRewardOpening, WithdrawalLeaf, BRIDGE_USER_ID, CLAIM_TREE_MAX_CAPACITY, INCLUSION_AGGREGATE_CAPACITIES, REWARD_PUBLICATION_FAMILY, SOURCE_CHECKPOINT_REWARD_OPENING_HEADER_BYTES, REWARD_SESSION_PROOF_FIELD_COUNT, WITHDRAWAL_PUBLICATION_FAMILY};
use psy_client_data::qdata::checkpoint::PsyCheckpointLeaf;
use psy_common_circuit::traits::{CreatableTarget, ToTargets};
use psy_network_circuit::gadgets::qdata::checkpoint::PsyCheckpointLeafGadget;
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers};
use psy_plonky2_common_circuits::{bridge::{aggregate_commitment::{self as hash, Bytes32Target, Domain, AggregateLeafTarget, WithdrawalLeafTarget}, aggregate_config::NetworkConfigTarget}, hash::keccak::keccak256_bytes_targets};
use super::deposit_aggregate::less_words;
use super::historical_merkle_proof::{historical_merkle_proof, HistoricalMerkleProofTarget};
use super::reward_session::{reward_ledger_window_hash, reward_session_seed, reward_session_summary, summary_path_root, RewardLedgerStateTargets, RewardLedgerStateValues, RewardLedgerWindowTargets};
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

pub struct RewardInclusionAggregateCircuit<const CAPACITY: usize> {
    pub circuit_data: CircuitData<F, PoseidonGoldilocksConfig, 2>,
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
    final_proof: ProofWithPublicInputsTarget<2>,
    final_state: RewardLedgerStateTargets,
    slots: Vec<RewardPayoutSlot>,
    user_common: CommonCircuitData<F, 2>,
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
    leaf_words: Vec<Target>,
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

fn source_checkpoint_reward_opening(
    builder: &mut CircuitBuilder<F, 2>, header: &[Target], leaves: &[Vec<Target>], count: Target,
) -> Bytes32Target {
    assert_eq!(header.len(), SOURCE_CHECKPOINT_REWARD_OPENING_HEADER_BYTES / 4);
    let mut words = source_domain(builder, b"Opening").to_vec();
    words.extend_from_slice(header);
    for leaf in leaves { words.extend_from_slice(leaf); }
    let header_bytes = builder.constant(F::from_canonical_usize(32 + SOURCE_CHECKPOINT_REWARD_OPENING_HEADER_BYTES));
    let length = builder.mul_const_add(F::from_canonical_usize(192), count, header_bytes);
    hash::keccak_prefix_words(builder, &words, length)
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
        let limb = amount[index];
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

fn constrain_reward_payout<const CAPACITY: usize>(
    builder: &mut CircuitBuilder<F, 2>, index: usize, count: Target, previous_user: Option<Target>,
    common: &CommonCircuitData<F, 2>, real_vk: &VerifierCircuitTarget, dummy_proof: &ProofWithPublicInputsTarget<2>,
    dummy_vk: &VerifierCircuitTarget, ledger_window: &RewardLedgerWindowTargets, ledger_final_user_root: HashOutTarget,
) -> RewardPayoutSlot {
    let zero = builder.zero();
    let one = builder.one();
    let slot = builder.constant(F::from_canonical_usize(index));
    let active = builder.is_less_than(CAPACITY.ilog2() as usize + 1, slot, count);
    let inactive = builder.not(active);
    let proof = builder.add_virtual_proof_with_pis(common);
    builder.conditionally_verify_proof::<PoseidonGoldilocksConfig>(active, &proof, real_vk, dummy_proof, dummy_vk, common);
    for &word in &proof.public_inputs { builder.connect_if_true(inactive, word, zero); }
    let state = RewardLedgerStateTargets::new(builder);
    for target in state.ledger_window_hash.elements.into_iter().chain(state.ledger_root.elements).chain(state.user_root.elements).chain(state.root.elements) {
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
    let mut leaf_words = Vec::with_capacity(48);
    for chunk in ledger_window.economic_domain.chunks(4) {
        let mut word = builder.zero();
        for byte in chunk { word = builder.mul_const_add(F::from_canonical_u32(256), word, *byte); }
        leaf_words.push(word);
    }
    leaf_words.extend(hash::word(builder, source_index, 32));
    leaf_words.extend(hash::word(builder, user_id, 32));
    leaf_words.extend(amount_words(builder, &std::array::from_fn(|i| proof.public_inputs[13 + i])));
    leaf_words.extend(hash::word_address(builder, recipient));
    leaf_words.extend(hash::word(builder, one, 1));
    for &word in &leaf_words { builder.connect_if_true(inactive, word, zero); }
    RewardPayoutSlot { proof, state, source_checkpoint_id, source, session_root, summary_siblings, leaf_words }
}



impl<const CAPACITY: usize> RewardInclusionAggregateCircuit<CAPACITY> {
    pub fn new(common: &CommonCircuitData<F, 2>, verifier: &VerifierOnlyCircuitData<PoseidonGoldilocksConfig, 2>, source_chain_count: usize) -> Self {
        assert!(INCLUSION_AGGREGATE_CAPACITIES.contains(&(CAPACITY as u32)));
        assert!((1..=8).contains(&source_chain_count));
        assert_eq!(common.num_public_inputs, REWARD_SESSION_PROOF_FIELD_COUNT);

        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let config = NetworkConfigTarget::new(&mut builder, source_chain_count);
        let real_vk = builder.constant_verifier_data(verifier);
        let (ledger_window, config_words, window_words, old_ledger_state_root) = reward_ledger_window(&mut builder, &config, &real_vk);
        builder.connect_hashes(ledger_window.start_root, old_ledger_state_root);
        let aggregate_capacity = builder.constant(F::from_canonical_usize(CAPACITY));
        let total_count = builder.add_virtual_target();
        let segment_count = builder.add_virtual_target();
        let segment_index = builder.add_virtual_target();
        let first_ordinal = builder.add_virtual_target();
        let count = builder.add_virtual_target();
        aggregate_segment(&mut builder, CAPACITY, total_count, segment_count, segment_index, first_ordinal, count, config.max_rewards);
        let zero = builder.zero();
        let one = builder.one();
        builder.connect(segment_index, zero);
        let empty = builder.is_equal(total_count, zero);
        let nonempty = builder.not(empty);
        let expected_segments = builder.select(empty, zero, one);
        builder.connect(segment_count, expected_segments);
        builder.connect(first_ordinal, zero);
        builder.connect(count, total_count);
        let single_segment_limit = builder.constant(F::from_canonical_usize(1024));
        builder.ensure_is_less_than_or_equal(32, total_count, single_segment_limit);
        let (dummy_proof, dummy_vk) = builder.dummy_proof_and_constant_vk_no_generator::<PoseidonGoldilocksConfig>(common).expect("user reward dummy");
        let final_proof = builder.add_virtual_proof_with_pis(common);
        builder.verify_proof::<PoseidonGoldilocksConfig>(&final_proof, &real_vk, common);
        let final_state = RewardLedgerStateTargets::new(&mut builder);
        builder.connect_hashes_if_true(nonempty, final_state.ledger_window_hash, ledger_window.hash);
        let tip_start = HashOutTarget { elements: std::array::from_fn(|i| final_proof.public_inputs[26 + i]) };
        let tip_end = HashOutTarget { elements: std::array::from_fn(|i| final_proof.public_inputs[30 + i]) };
        let tip_window = HashOutTarget { elements: std::array::from_fn(|i| final_proof.public_inputs[22 + i]) };
        builder.connect_hashes_if_true(empty, tip_start, old_ledger_state_root);
        builder.connect_hashes_if_true(empty, tip_end, old_ledger_state_root);
        builder.connect_hashes_if_true(empty, tip_window, ledger_window.hash);
        builder.connect_if_true(empty, final_proof.public_inputs[21], zero);
        builder.connect_hashes(final_state.root, HashOutTarget { elements: std::array::from_fn(|i| final_proof.public_inputs[30 + i]) });
        builder.connect_hashes(HashOutTarget { elements: std::array::from_fn(|i| final_proof.public_inputs[i]) }, ledger_window.end_checkpoint_root);
        builder.connect_if_true(nonempty, final_state.session_count, total_count);
        builder.connect_if_true(nonempty, final_state.unfinished_session_count, zero);
        let mut slots = Vec::with_capacity(CAPACITY);
        let mut previous_user = None;
        let mut commits = [hash::constant_bytes32(&mut builder, [0; 32]); CAPACITY];
        for index in 0..CAPACITY {
            let slot = constrain_reward_payout::<CAPACITY>(&mut builder, index, count, previous_user, common, &real_vk, &dummy_proof, &dummy_vk, &ledger_window, final_state.user_root);
            commits[index] = source_checkpoint_reward_leaf_commit(&mut builder, &slot.leaf_words);
            previous_user = Some(slot.proof.public_inputs[4]);
            slots.push(slot);
        }
        let mut opening_header = config_words.to_vec();
        opening_header.extend(window_words);
        opening_header.extend(hash::word(&mut builder, ledger_window.end_checkpoint_id, 32));
        opening_header.extend(hash::encode_hash4(&mut builder, ledger_window.end_checkpoint_root.elements));
        opening_header.extend(hash::word(&mut builder, count, 32));
        let leaf_words = slots.iter().map(|slot| slot.leaf_words.clone()).collect::<Vec<_>>();
        let opening_digest = source_checkpoint_reward_opening(&mut builder, &opening_header, &leaf_words, count);
        let claim_root = claim_tree_root::<2, CAPACITY>(&mut builder, &commits, count);
        let family = builder.constant(F::from_canonical_u8(REWARD_PUBLICATION_FAMILY));
        let end_id = [ledger_window.end_checkpoint_id, zero];
        let header_digest = header_digest_targets(&mut builder, family, config_words, window_words, end_id, ledger_window.end_checkpoint_root.elements,
            [aggregate_capacity, total_count, segment_count, segment_index, first_ordinal, count],
            &[old_ledger_state_root.elements, std::array::from_fn(|i| final_proof.public_inputs[30 + i])], opening_digest, claim_root);
        let prefix = [1, 7, REWARD_PUBLICATION_FAMILY as u32, 0].map(|value| builder.constant(F::from_canonical_u32(value)));
        builder.register_public_inputs(&prefix);
        builder.register_public_inputs(&opening_digest);
        builder.register_public_inputs(&claim_root);
        builder.register_public_inputs(&header_digest);
        let circuit_data = builder.build::<PoseidonGoldilocksConfig>();
        assert_eq!(circuit_data.common.num_public_inputs, AGGREGATE_PI_LEN);
        Self { circuit_data, config, config_hash: config_words, window_id: window_words, economic_domain: ledger_window.economic_domain,
            start_root: ledger_window.start_root, end_id: ledger_window.end_checkpoint_id, end_root: ledger_window.end_checkpoint_root, old_ledger_state_root,
            aggregate_capacity, total_count, segment_count, segment_index, first_ordinal, count, opening_digest, claim_tree_root: claim_root,
            final_proof, final_state, slots, user_common: common.clone() }
    }

    pub fn set_witness(&self, witness: &mut PartialWitness<F>, config: &NetworkConfig, opening: &SourceCheckpointRewardOpening,
        header: &InclusionAggregateHeader, tip: &RewardLedgerFinalProof<'_>, leaves: &[SourceCheckpointRewardAggregateLeaf<'_>]) -> anyhow::Result<()>
    {
        header.validate()?;
        opening.encode()?;
        anyhow::ensure!(header.family == REWARD_PUBLICATION_FAMILY, "reward publication family mismatch");
        anyhow::ensure!(header.segment_index == 0 && header.first_ordinal == 0, "reward publication is one segment");
        anyhow::ensure!(header.segment_count == u32::from(header.count != 0), "reward publication segment count differs from count");
        anyhow::ensure!(header.total_count as usize == leaves.len() && header.count as usize == leaves.len(), "reward publication count differs from leaves");
        anyhow::ensure!(header.total_count <= config.max_rewards && header.total_count <= 1024, "reward publication exceeds the single segment");
        anyhow::ensure!(header.withdrawal_roots.is_empty(), "reward publication carries withdrawal roots");
        let (Some(old_root), Some(new_root)) = (header.old_ledger_state_root, header.new_ledger_state_root) else { anyhow::bail!("reward publication ledger-state roots missing"); };
        anyhow::ensure!(header.config_hash == opening.config_hash && header.window_id == opening.window_id
            && header.end_checkpoint_id == opening.end_checkpoint_id && header.end_checkpoint_root == opening.end_checkpoint_root,
            "reward aggregate window differs from opening");
        anyhow::ensure!(config.config_hash()? == header.config_hash, "aggregate configuration mismatch");
        anyhow::ensure!(opening.leaves.len() == leaves.len() && opening.leaves.iter().zip(leaves).all(|(leaf, payout)| leaf == payout.leaf), "reward opening differs from leaves");
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
        anyhow::ensure!(leaves.iter().all(|leaf| leaf.leaf.economic_domain == economic_domain), "reward economic domain differs inside one publication");
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
        witness.set_proof_with_pis_target(&self.final_proof, tip.proof)?;
        self.final_state.set_witness(witness, tip.state)?;
        let dummy_data = plonky2::recursion::dummy_circuit::dummy_circuit::<F, PoseidonGoldilocksConfig, 2>(&self.user_common);
        let dummy = dummy_proof(&dummy_data, Default::default())?;
        let empty_leaf = PsyCheckpointLeaf::default();
        for (index, slot) in self.slots.iter().enumerate() {
            if let Some(leaf) = leaves.get(index) {
                anyhow::ensure!(leaf.proof.public_inputs.len() == REWARD_SESSION_PROOF_FIELD_COUNT, "reward leaf width mismatch");
                anyhow::ensure!(leaf.leaf.source_checkpoint_id == u64::from(leaf.source_checkpoint_id), "reward source checkpoint differs from leaf");
                set_bytes(witness, &slot.leaf_words, &leaf.leaf.encode()?)?;
                witness.set_proof_with_pis_target(&slot.proof, leaf.proof)?;
                slot.state.set_witness(witness, leaf.state)?;
                witness.set_target(slot.source_checkpoint_id, F::from_canonical_u32(leaf.source_checkpoint_id))?;
                slot.source.checkpoint_leaf.set_witness(witness, leaf.source_leaf)?;
                for (target, sibling) in slot.source.path.siblings.iter().zip(leaf.source_siblings) { set_hash4(witness, target.elements, *sibling)?; }
                set_hash4(witness, slot.session_root.elements, leaf.session_root)?;
                for (target, sibling) in slot.summary_siblings.iter().zip(leaf.summary_siblings) { set_hash4(witness, target.elements, *sibling)?; }
            } else {
                for &word in &slot.leaf_words { witness.set_target(word, F::ZERO)?; }
                witness.set_proof_with_pis_target(&slot.proof, &dummy)?;
                slot.state.set_witness(witness, &RewardLedgerStateValues { ledger_window_hash: [0; 4], ledger_root: [0; 4], user_root: [0; 4], session_count: 0, unfinished_session_count: 0 })?;
                witness.set_target(slot.source_checkpoint_id, F::ZERO)?;
                slot.source.checkpoint_leaf.set_witness(witness, &empty_leaf)?;
                for sibling in slot.source.path.siblings.iter().chain(&slot.summary_siblings) { set_hash4(witness, sibling.elements, [0; 4])?; }
                set_hash4(witness, slot.session_root.elements, [0; 4])?;
            }
        }
        Ok(())
    }

    pub fn prove(&self, config: &NetworkConfig, opening: &SourceCheckpointRewardOpening, header: &InclusionAggregateHeader,
        tip: &RewardLedgerFinalProof<'_>, leaves: &[SourceCheckpointRewardAggregateLeaf<'_>]) -> anyhow::Result<ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>>
    {
        let mut witness = PartialWitness::new();
        self.set_witness(&mut witness, config, opening, header, tip, leaves)?;
        self.circuit_data.prove(witness)
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

    #[test]
    fn reward_publication_proves_empty_and_rejects_digest_tampering() {
        use psy_crypto::hash::traits::qhashable::QFieldHashable;
        use plonky2::plonk::config::Hasher;
        let config = config(&[0]);
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
        let (proof, state) = session.prove_identity(&config, &window, &leaf, &path, &roots, None).unwrap();
        session.circuit_data.verify(proof.clone()).unwrap();
        let aggregate = RewardInclusionAggregateCircuit::<1024>::new(&session.circuit_data.common, &session.circuit_data.verifier_only, 1);
        let opening = SourceCheckpointRewardOpening { config_hash: window.config_hash, window_id: window.window_id,
            end_checkpoint_id: 7, end_checkpoint_root: window.end_checkpoint_root, leaves: Vec::new() };
        let header = InclusionAggregateHeader { family: REWARD_PUBLICATION_FAMILY, config_hash: opening.config_hash,
            window_id: opening.window_id, end_checkpoint_id: opening.end_checkpoint_id, end_checkpoint_root: opening.end_checkpoint_root,
            aggregate_capacity: 1024, total_count: 0, segment_count: 0, segment_index: 0, first_ordinal: 0, count: 0,
            withdrawal_roots: Vec::new(), old_ledger_state_root: Some(window.start_root), new_ledger_state_root: Some(window.start_root),
            opening_digest: opening.opening_digest().unwrap(),
            claim_tree_root: psy_client_data::bridge_aggregate::build_inclusion_aggregate_tree(&[], 1024).unwrap()[0] };
        let tip = RewardLedgerFinalProof { proof: &proof, state: &state };
        let published = aggregate.prove(&config, &opening, &header, &tip, &[]).unwrap();
        assert_eq!(published.public_inputs[4..12], header.opening_digest.chunks_exact(4).map(|word| F::from_canonical_u32(u32::from_be_bytes(word.try_into().unwrap()))).collect::<Vec<_>>());
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
        let mut next_window = window.clone();
        next_window.window_id[0] ^= 1;
        let (next, next_state) = session.prove_identity(&config, &next_window, &leaf, &path, &roots, Some((&proof, &state))).unwrap();
        session.circuit_data.verify(next.clone()).unwrap();
        assert_eq!(next_state, state);
        assert_eq!(next.public_inputs[26..34], proof.public_inputs[26..34]);
        assert_ne!(next.public_inputs[22..26], proof.public_inputs[22..26]);
        let mut invalid_predecessor = proof.clone();
        invalid_predecessor.public_inputs[30] += F::ONE;
        assert!(session.prove_identity(&config, &next_window, &leaf, &path, &roots, Some((&invalid_predecessor, &state))).is_err());
        let mut invalid_state = state;
        invalid_state.session_count += 1;
        assert!(session.prove_identity(&config, &next_window, &leaf, &path, &roots, Some((&proof, &invalid_state))).is_err());
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
