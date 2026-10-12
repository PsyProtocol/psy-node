//! Direct bridge claim circuits.
//!
//! Withdrawal claims authenticate namespace-6 burns under the finalized
//! checkpoint. Reward claims verify one pinned `RewardClaimBatchCircuit` proof.
//! The business statement is registered before any verifier suffix.
//! UCON authenticates the raw CSTATE root; a separate GCON path authenticates
//! the installed full CLV3 contract definition at the same contract identifier.

use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::{hash_types::{HashOut, HashOutTarget}, poseidon::PoseidonHash},
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{Hasher, PoseidonGoldilocksConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf;
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::traits::qhashable::QFieldHashable;
use serde::{Deserialize, Serialize};
use psy_common_circuit::{
    builder::comparison::CircuitBuilderComparison,
    hash::merkle::gadgets::imt_contract_state_update::IMTLeafTargets,
    traits::CreatableTarget,
    u32::{arithmetic_u32::{CircuitBuilderU32, U32Target}, witness::WitnessU32},
};
use psy_config::network_constants::{CHECKPOINT_TREE_HEIGHT, GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT};
use psy_client_data::qdata::{contract::PsyContractLeaf, user::PsyUserLeaf, user_contract_state::UserContractState};
use psy_network_circuit::gadgets::qdata::{
    contract::PsyContractLeafGadget,
    user_contract_state::UserContractStateGadget,
};
use psy_plonky2_basic_helpers::builder::pad_circuit::CircuitBuilderQEDCommonGates;
use psy_plonky2_common_circuits::hash::merkle::gadgets::merkle_proof::MerkleProofGadget;

use super::reward_chain::REWARD_ROOT_STATEMENT_LEN;
use super::reward_claim_batch::REWARD_CLAIM_BATCH_STATEMENT_LEN;
use crate::{
    bridge::gadgets::anchor_to_end::AnchorToEndTarget,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

pub const BRIDGE_CLAIM_CAPACITY: usize = 32;
pub const BRIDGE_WITHDRAWAL_CLAIM_WORDS: usize = 10;
pub const BRIDGE_REWARD_CLAIM_WORDS: usize = 15;
pub const BRIDGE_WITHDRAWAL_CLAIM_STATEMENT_LEN: usize =
    14 + BRIDGE_CLAIM_CAPACITY * BRIDGE_WITHDRAWAL_CLAIM_WORDS * 8;
pub const BRIDGE_REWARD_CLAIM_STATEMENT_LEN: usize =
    6 + BRIDGE_CLAIM_CAPACITY * BRIDGE_REWARD_CLAIM_WORDS * 8;
pub const BRIDGE_REWARD_CONTRACT_ID: u64 = 7;
pub const BRIDGE_CLAIM_DEGREE_BITS: usize = 16;

const STATE_HEIGHT: usize = 32;
const KIND_WITHDRAWAL: u32 = 1;
const KIND_REWARD: u32 = 2;
const WITHDRAWAL_NAMESPACE: u64 = 6;

/// Installed immutable token approval.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeTokenPolicy {
    pub chain_index: u8,
    pub token_contract_id: u32,
    pub token_address: [u32; 8],
    pub approved_leaf: PsyContractLeaf<F>,
    pub map_base: u32,
    pub capacity: u32,
}

#[derive(Clone, Debug)]
pub struct BridgeWithdrawalClaimWitness {
    pub policy_ordinal: u8,
    pub user_contract: UserContractState<F>,
    pub user_siblings: [HashOut<F>; GLOBAL_USER_TREE_HEIGHT as usize],
    pub contract_siblings: [HashOut<F>; GLOBAL_CONTRACT_TREE_HEIGHT as usize],
    pub global_contract_siblings: [HashOut<F>; GLOBAL_CONTRACT_TREE_HEIGHT as usize],
    pub member_index: u32,
    pub member: IMTContractStateLeaf<F>,
    pub member_siblings: [HashOut<F>; STATE_HEIGHT],
    pub sentinel: IMTContractStateLeaf<F>,
    pub sentinel_siblings: [HashOut<F>; STATE_HEIGHT],
    pub recipient: [u32; 8],
    pub token_address: [u32; 8],
    pub amount: [u32; 8],
    pub nonce: [u32; 8],
}

#[derive(Clone, Debug)]
pub struct BridgeWithdrawalClaimInput {
    pub end_checkpoint_id: u32,
    pub end_checkpoint_root: HashOut<F>,
    pub end_gusr: HashOut<F>,
    pub end_gcon: HashOut<F>,
    pub claims: Vec<BridgeWithdrawalClaimWitness>,
}

#[derive(Clone, Debug)]
pub struct BridgeRewardClaimWitness {
    pub statement_index: u32,
    pub anchor_checkpoint_id: u32,
    pub anchor_leaf: HashOut<F>,
    pub anchor_siblings: [HashOut<F>; CHECKPOINT_TREE_HEIGHT as usize],
}

#[derive(Clone, Debug)]
pub struct BridgeRewardClaimInput {
    pub end_checkpoint_id: u32,
    /// Authenticated endpoint tree root, including when the reward batch is empty.
    pub end_checkpoint_root: HashOut<F>,
    pub claims: Vec<BridgeRewardClaimWitness>,
    pub batch_proof: ProofWithPublicInputs<F, C, D>,
}

#[derive(Debug)]
pub struct BridgeWithdrawalPaymentTargets {
    pub recipient: [U32Target; 8],
    pub amount: [U32Target; 8],
    pub nonce: [U32Target; 8],
}

pub struct BridgeWithdrawalClaimTargets {
    pub count: Target,
    pub end_checkpoint_id: Target,
    pub end_checkpoint_root: HashOutTarget,
    pub end_gusr: HashOutTarget,
    pub end_gcon: HashOutTarget,
    pub claims: [[[U32Target; 8]; BRIDGE_WITHDRAWAL_CLAIM_WORDS]; BRIDGE_CLAIM_CAPACITY],
    pub users: [UserContractStateGadget; BRIDGE_CLAIM_CAPACITY],
    pub contracts: [PsyContractLeafGadget; BRIDGE_CLAIM_CAPACITY],
    pub user_paths: [MerkleProofGadget; BRIDGE_CLAIM_CAPACITY],
    pub contract_paths: [MerkleProofGadget; BRIDGE_CLAIM_CAPACITY],
    pub global_contract_paths: [MerkleProofGadget; BRIDGE_CLAIM_CAPACITY],
    pub members: [IMTLeafTargets; BRIDGE_CLAIM_CAPACITY],
    pub member_paths: [MerkleProofGadget; BRIDGE_CLAIM_CAPACITY],
    pub sentinels: [IMTLeafTargets; BRIDGE_CLAIM_CAPACITY],
    pub sentinel_paths: [MerkleProofGadget; BRIDGE_CLAIM_CAPACITY],
    pub ordinals: [Target; BRIDGE_CLAIM_CAPACITY],
    pub payments: [BridgeWithdrawalPaymentTargets; BRIDGE_CLAIM_CAPACITY],
}

pub struct BridgeRewardClaimTargets {
    pub count: Target,
    pub end_checkpoint_id: Target,
    pub end_checkpoint_root: HashOutTarget,
    pub claims: [[[U32Target; 8]; BRIDGE_REWARD_CLAIM_WORDS]; BRIDGE_CLAIM_CAPACITY],
    pub indices: [Target; BRIDGE_CLAIM_CAPACITY],
    pub anchors: [AnchorToEndTarget; BRIDGE_CLAIM_CAPACITY],
    pub batch_proof: ProofWithPublicInputsTarget<D>,
}

pub struct BridgeWithdrawalClaimCircuit {
    pub targets: BridgeWithdrawalClaimTargets,
    pub circuit_data: CircuitData<F, C, D>,
    pub fingerprint: parth_core::pgoldilocks::QHashOut<F>,
    policies: Vec<BridgeTokenPolicy>,
}

pub struct BridgeRewardClaimCircuit {
    pub targets: BridgeRewardClaimTargets,
    pub circuit_data: CircuitData<F, C, D>,
    pub fingerprint: parth_core::pgoldilocks::QHashOut<F>,
}

fn words(builder: &mut CircuitBuilder<F, D>) -> [U32Target; 8] {
    std::array::from_fn(|_| builder.add_virtual_u32_target())
}

fn word_targets(word: [U32Target; 8]) -> [Target; 8] {
    word.map(|limb| limb.0)
}



fn bounded(builder: &mut CircuitBuilder<F, D>, value: Target, bits: usize) -> [U32Target; 8] {
    builder.range_check(value, bits);
    let mut word = [builder.zero_u32(); 8];
    word[7] = U32Target(value);
    word
}

fn canonical_root_word(builder: &mut CircuitBuilder<F, D>, limb: Target) -> [U32Target; 8] {
    let (low, high) = builder.split_low_high(limb, 32, 64);
    let maximum = builder.constant(F::from_canonical_u32(u32::MAX));
    let high_maximum = builder.is_equal(high, maximum);
    let noncanonical = builder.mul(high_maximum.target, low);
    builder.assert_zero(noncanonical);
    let mut word = [builder.zero_u32(); 8];
    word[6] = U32Target(high);
    word[7] = U32Target(low);
    word
}

fn select_word(
    builder: &mut CircuitBuilder<F, D>,
    active: BoolTarget,
    value: [U32Target; 8],
) -> [U32Target; 8] {
    let zero = builder.zero_u32();
    std::array::from_fn(|index| builder.select_u32(active, value[index], zero))
}
fn select_installed(builder: &mut CircuitBuilder<F, D>, ordinal: Target, values: &[F]) -> Target {
    let mut selected = builder.constant(values[0]);
    for (position, &value) in values.iter().enumerate().skip(1) {
        let position = builder.constant(F::from_canonical_usize(position));
        let matches = builder.is_equal(ordinal, position);
        let value = builder.constant(value);
        selected = builder.select(matches, value, selected);
    }
    selected
}

fn select_installed_hash(builder: &mut CircuitBuilder<F, D>, ordinal: Target, values: &[HashOut<F>]) -> HashOutTarget {
    HashOutTarget {
        elements: std::array::from_fn(|index| {
            select_installed(builder, ordinal, &values.iter().map(|value| value.elements[index]).collect::<Vec<_>>())
        }),
    }
}

fn contract_leaf_hash(leaf: &PsyContractLeaf<F>) -> HashOut<F> {
    leaf.qfhash::<PoseidonHash>().0
}

fn active_flag(builder: &mut CircuitBuilder<F, D>, index: Target, count: Target) -> BoolTarget {
    builder.is_less_than(6, index, count)
}

fn connect_if(
    builder: &mut CircuitBuilder<F, D>,
    active: BoolTarget,
    left: Target,
    right: Target,
) {
    let selected = builder.select(active, right, left);
    builder.connect(left, selected);
}

fn connect_hash_if(
    builder: &mut CircuitBuilder<F, D>,
    active: BoolTarget,
    left: HashOutTarget,
    right: HashOutTarget,
) {
    for index in 0..4 {
        connect_if(builder, active, left.elements[index], right.elements[index]);
    }
}


fn assert_sorted<const WORDS: usize>(
    builder: &mut CircuitBuilder<F, D>,
    count: Target,
    claims: &[[[U32Target; 8]; WORDS]; BRIDGE_CLAIM_CAPACITY],
) {
    let one = builder.one();
    for slot in 1..BRIDGE_CLAIM_CAPACITY {
        let previous = builder.constant(F::from_canonical_usize(slot - 1));
        let current = builder.constant(F::from_canonical_usize(slot));
        let previous_active = builder.is_less_than(6, previous, count);
        let current_active = builder.is_less_than(6, current, count);
        let both = builder.and(previous_active, current_active);
        let mut less = builder._false();
        let mut prefix_equal = builder._true();
        for word in [1, 2, 3, 4] {
            for limb in 0..8 {
                let left = claims[slot - 1][word][limb].0;
                let right = claims[slot][word][limb].0;
                let limb_less = builder.is_less_than(32, left, right);
                let first = builder.and(prefix_equal, limb_less);
                less = BoolTarget::new_unsafe(builder.select(less, one, first.target));
                let limb_equal = builder.is_equal(left, right);
                prefix_equal = builder.and(prefix_equal, limb_equal);
            }
        }
        let not_both = builder.not(both);
        let valid = builder.or(not_both, less);
        builder.connect(valid.target, one);
    }
}

fn withdrawal_key_value(
    builder: &mut CircuitBuilder<F, D>,
    sender: Target,
    recipient: [U32Target; 8],
    token: [U32Target; 8],
    amount: [U32Target; 8],
    nonce: [U32Target; 8],
    chain: Target,
) -> (HashOutTarget, HashOutTarget) {
    let nonce_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(nonce.map(|limb| limb.0).to_vec());
    let namespace = builder.constant(F::from_canonical_u64(WITHDRAWAL_NAMESPACE));
    let mut key_inputs = vec![namespace];
    key_inputs.extend(nonce_hash.elements);
    let key = builder.hash_n_to_hash_no_pad::<PoseidonHash>(key_inputs);
    let mut value_inputs = vec![sender];
    for word in [recipient, token, amount, nonce] {
        value_inputs.extend(word.map(|limb| limb.0));
    }
    value_inputs.push(chain);
    debug_assert_eq!(value_inputs.len(), 34);
    let value = builder.hash_n_to_hash_no_pad::<PoseidonHash>(value_inputs);
    (key, value)
}

fn build_withdrawal(policies: &[BridgeTokenPolicy]) -> BridgeWithdrawalClaimCircuit {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    builder.add_qed_type_d_common_gates();
    let zero = builder.zero();
    let one = builder.one();
    let zero_hash = builder.constant_hash(HashOut::ZERO);
    let count = builder.add_virtual_target();
    builder.range_check(count, 6);
    let maximum_count = builder.constant(F::from_canonical_usize(BRIDGE_CLAIM_CAPACITY));
    builder.ensure_is_less_than_or_equal(6, count, maximum_count);
    let end_checkpoint_id = builder.add_virtual_target();
    builder.range_check(end_checkpoint_id, 32);
    let end_checkpoint_root = builder.add_virtual_hash();
    let end_gusr = builder.add_virtual_hash();
    let end_gcon = builder.add_virtual_hash();
    let policy_chains: Vec<F> = policies.iter().map(|policy| F::from_canonical_u32(u32::from(policy.chain_index))).collect();
    let policy_contracts: Vec<F> = policies.iter().map(|policy| F::from_canonical_u32(policy.token_contract_id)).collect();
    let policy_tokens: [Vec<F>; 8] = std::array::from_fn(|limb| policies.iter().map(|policy| F::from_canonical_u32(policy.token_address[limb])).collect());
    let policy_bases: Vec<F> = policies.iter().map(|policy| F::from_canonical_u32(policy.map_base)).collect();
    let policy_capacities: Vec<F> = policies.iter().map(|policy| F::from_canonical_u32(policy.capacity)).collect();
    let approved_hashes: Vec<HashOut<F>> = policies.iter().map(|policy| contract_leaf_hash(&policy.approved_leaf)).collect();
    let policy_count = builder.constant(F::from_canonical_usize(policies.len()));
    let state_height = builder.constant(F::from_canonical_usize(STATE_HEIGHT));
    let kind = builder.constant(F::from_canonical_u32(KIND_WITHDRAWAL));
    let kind_word = bounded(&mut builder, kind, 8);
    let mut claims = [[[builder.zero_u32(); 8]; BRIDGE_WITHDRAWAL_CLAIM_WORDS]; BRIDGE_CLAIM_CAPACITY];
    let mut ordinals = Vec::new();
    let mut payments = Vec::new();
    let mut users = Vec::new();
    let mut contracts = Vec::new();
    let mut user_paths = Vec::new();
    let mut contract_paths = Vec::new();
    let mut global_contract_paths = Vec::new();
    let mut members = Vec::new();
    let mut member_paths = Vec::new();
    let mut sentinels = Vec::new();
    let mut sentinel_paths = Vec::new();
    for slot in 0..BRIDGE_CLAIM_CAPACITY {
        let slot_target = builder.constant(F::from_canonical_usize(slot));
        let active = active_flag(&mut builder, slot_target, count);
        let inactive = builder.not(active);
        let ordinal = builder.add_virtual_target();
        builder.range_check(ordinal, 8);
        connect_if(&mut builder, inactive, ordinal, zero);
        builder.ensure_is_less_than(8, ordinal, policy_count);
        ordinals.push(ordinal);
        let policy_chain = select_installed(&mut builder, ordinal, &policy_chains);
        let policy_contract = select_installed(&mut builder, ordinal, &policy_contracts);
        let policy_token = std::array::from_fn(|limb| U32Target(select_installed(&mut builder, ordinal, &policy_tokens[limb])));
        let base = select_installed(&mut builder, ordinal, &policy_bases);
        let capacity = select_installed(&mut builder, ordinal, &policy_capacities);
        let first = builder.add(base, one);
        let user = UserContractStateGadget::add_virtual_to(&mut builder);
        let contract = PsyContractLeafGadget::create_virtual(&mut builder);
        builder.range_check(user.user_leaf.user_id, 32);
        builder.connect(contract.state_tree_height, state_height);
        let user_hash = user.user_leaf.to_hash::<PoseidonHash, F, D>(&mut builder);
        let user_path = MerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, GLOBAL_USER_TREE_HEIGHT as usize);
        connect_if(&mut builder, active, user_path.index, user.user_leaf.user_id);
        builder.connect_hashes(user_path.value, user_hash);
        connect_hash_if(&mut builder, active, user_path.root, end_gusr);
        // UCON leaves are raw CSTATE roots, not contract-definition hashes.
        let contract_path = MerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, GLOBAL_CONTRACT_TREE_HEIGHT as usize);
        connect_if(&mut builder, active, contract_path.index, policy_contract);
        builder.connect_hashes(contract_path.value, user.start_contract_state_root);
        connect_hash_if(&mut builder, active, contract_path.root, user.user_leaf.user_state_tree_root);
        // GCON independently proves the installed full CLV3 leaf at that same id.
        let contract_hash = contract.to_hash::<PoseidonHash, F, D>(&mut builder);
        let approved_hash = select_installed_hash(&mut builder, ordinal, &approved_hashes);
        connect_hash_if(&mut builder, active, contract_hash, approved_hash);
        let global_contract_path = MerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, GLOBAL_CONTRACT_TREE_HEIGHT as usize);
        connect_if(&mut builder, active, global_contract_path.index, policy_contract);
        builder.connect_hashes(global_contract_path.value, contract_hash);
        connect_hash_if(&mut builder, active, global_contract_path.root, end_gcon);
        let member = IMTLeafTargets::add_virtual_to(&mut builder);
        let member_path = MerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, STATE_HEIGHT);
        let member_hash = member.hash::<PoseidonHash, F, D>(&mut builder);
        builder.connect_hashes(member_path.value, member_hash);
        connect_hash_if(&mut builder, active, member_path.root, user.start_contract_state_root);
        let sentinel = IMTLeafTargets::add_virtual_to(&mut builder);
        let sentinel_path = MerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, STATE_HEIGHT);
        let sentinel_hash = sentinel.hash::<PoseidonHash, F, D>(&mut builder);
        builder.connect_hashes(sentinel_path.value, sentinel_hash);
        connect_if(&mut builder, active, sentinel_path.index, base);
        connect_hash_if(&mut builder, active, sentinel_path.root, user.start_contract_state_root);
        let count_n = sentinel.value.elements[0];
        builder.range_check(count_n, 32);
        for limb in 1..4 { connect_if(&mut builder, active, sentinel.value.elements[limb], zero); }
        connect_hash_if(&mut builder, active, sentinel.key, zero_hash);
        // Select a valid dummy interval before comparisons: inactive index zero
        // must never be compared against base - 1 in the field.
        let active_count = builder.select(active, count_n, one);
        builder.ensure_is_greater_than(32, active_count, zero);
        builder.ensure_is_less_than_or_equal(32, active_count, capacity);
        let occupied = builder.add(base, active_count);
        let member_index = builder.select(active, member_path.index, first);
        builder.ensure_is_greater_than(32, member_index, base);
        builder.ensure_is_less_than_or_equal(32, member_index, occupied);
        let next_is_zero = builder.is_equal(member.next_index, zero);
        let next_key_is_zero = builder.is_zero_hash(member.next_key);
        connect_if(&mut builder, active, next_is_zero.target, next_key_is_zero.target);
        let successor = builder.select(next_is_zero, first, member.next_index);
        let successor = builder.select(active, successor, first);
        builder.ensure_is_greater_than_or_equal(32, successor, first);
        builder.ensure_is_less_than_or_equal(32, successor, occupied);
        let chain = bounded(&mut builder, user.checkpoint_id, 8);
        let contract_id = bounded(&mut builder, user.contract_id, 24);
        let sender = bounded(&mut builder, user.user_leaf.user_id, 32);
        let recipient = words(&mut builder);
        let amount = words(&mut builder);
        let nonce = words(&mut builder);
        payments.push(BridgeWithdrawalPaymentTargets { recipient, amount, nonce });
        for word in [recipient, amount, nonce] {
            for limb in word { connect_if(&mut builder, inactive, limb.0, zero); }
        }
        for index in 0..6 { connect_if(&mut builder, active, amount[index].0, zero); }
        for index in 0..3 { connect_if(&mut builder, active, recipient[index].0, zero); }
        // §26.3.4: every recipient and nonce limb is a canonical u32; recipient is
        // a 160-bit address, so its high three limbs are zero, and the nonce is a
        // full 256-bit integer.
        for word in [recipient, nonce] {
            for limb in word { builder.range_check(limb.0, 32); }
        }
        let amount_sum = builder.add(amount[6].0, amount[7].0);
        let amount_is_zero = builder.is_equal(amount_sum, zero);
        connect_if(&mut builder, active, amount_is_zero.target, zero);
        // §26.3.4: amount is positive and below the Goldilocks modulus. Limbs 6..7
        // carry its canonical 64-bit value: each below 2^32, and the pair never
        // reaching 2^64 - 2^32 + 1.
        builder.range_check(amount[6].0, 32);
        builder.range_check(amount[7].0, 32);
        let u32_maximum = builder.constant(F::from_canonical_u32(u32::MAX));
        let amount_high_is_maximum = builder.is_equal(amount[6].0, u32_maximum);
        let amount_noncanonical = builder.mul(amount_high_is_maximum.target, amount[7].0);
        builder.assert_zero(amount_noncanonical);
        let (key, value) = withdrawal_key_value(&mut builder, sender[7].0, recipient, policy_token, amount, nonce, chain[7].0);
        connect_hash_if(&mut builder, active, member.key, key);
        connect_hash_if(&mut builder, active, member.value, value);
        claims[slot][0] = select_word(&mut builder, active, kind_word);
        claims[slot][1] = select_word(&mut builder, active, chain);
        claims[slot][2] = select_word(&mut builder, active, sender);
        claims[slot][3] = select_word(&mut builder, active, contract_id);
        claims[slot][4] = select_word(&mut builder, active, nonce);
        claims[slot][8] = select_word(&mut builder, active, recipient);
        claims[slot][9] = select_word(&mut builder, active, amount);
        connect_if(&mut builder, active, chain[7].0, policy_chain);
        connect_if(&mut builder, active, contract_id[7].0, policy_contract);
        users.push(user);
        contracts.push(contract);
        user_paths.push(user_path);
        contract_paths.push(contract_path);
        global_contract_paths.push(global_contract_path);
        members.push(member);
        member_paths.push(member_path);
        sentinels.push(sentinel);
        sentinel_paths.push(sentinel_path);
    }
    assert_sorted(&mut builder, count, &claims);
    let mut statement = vec![count, end_checkpoint_id];
    statement.extend(end_checkpoint_root.elements);
    statement.extend(end_gusr.elements);
    statement.extend(end_gcon.elements);
    for claim in &claims {
        for word in claim { statement.extend(word_targets(*word)); }
    }
    assert_eq!(statement.len(), BRIDGE_WITHDRAWAL_CLAIM_STATEMENT_LEN);
    builder.register_public_inputs(&statement);
    while builder.num_gates() < 1 << BRIDGE_CLAIM_DEGREE_BITS {
        builder.add_gate(plonky2::gates::noop::NoopGate, vec![]);
    }
    let circuit_data = builder.build::<C>();
    BridgeWithdrawalClaimCircuit {
        targets: BridgeWithdrawalClaimTargets {
            count, end_checkpoint_id, end_checkpoint_root, end_gusr, end_gcon, claims,
            users: users.try_into().unwrap(), contracts: contracts.try_into().unwrap(),
            user_paths: user_paths.try_into().unwrap(), contract_paths: contract_paths.try_into().unwrap(),
            global_contract_paths: global_contract_paths.try_into().unwrap(),
            members: members.try_into().unwrap(), member_paths: member_paths.try_into().unwrap(),
            sentinels: sentinels.try_into().unwrap(), sentinel_paths: sentinel_paths.try_into().unwrap(),
            ordinals: ordinals.try_into().unwrap(), payments: payments.try_into().unwrap(),
        },
        fingerprint: parth_core::pgoldilocks::QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only)),
        circuit_data,
        policies: policies.to_vec(),
    }
}

fn reward_word(
    builder: &mut CircuitBuilder<F, D>,
    active: BoolTarget,
    statement: &[Target],
    offset: usize,
    little_endian: bool,
) -> [U32Target; 8] {
    let mut word = [builder.zero_u32(); 8];
    let zero = builder.zero();
    for index in 0..8 {
        let source = if little_endian { 7 - index } else { index };
        word[index] = U32Target(builder.select(active, statement[offset + source], zero));
        builder.range_check(word[index].0, 32);
    }
    word
}

fn build_reward(
    batch_common: &CommonCircuitData<F, D>,
    batch_verifier: &VerifierOnlyCircuitData<C, D>,
    ethereum_index: u8,
) -> BridgeRewardClaimCircuit {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    builder.add_qed_type_d_common_gates();
    let zero = builder.zero();
    let one = builder.one();
    let proof = builder.add_virtual_proof_with_pis(batch_common);
    let verifier = builder.constant_verifier_data(batch_verifier);
    builder.verify_proof::<C>(&proof, &verifier, batch_common);
    let suffix = proof.public_inputs.len() - REWARD_CLAIM_BATCH_STATEMENT_LEN;
    assert_eq!(suffix, 4 + 4 * verifier.constants_sigmas_cap.0.len());
    for index in 0..4 {
        builder.connect(
            proof.public_inputs[REWARD_CLAIM_BATCH_STATEMENT_LEN + index],
            verifier.circuit_digest.elements[index],
        );
    }
    for (index, cap) in verifier.constants_sigmas_cap.0.iter().enumerate() {
        for limb in 0..4 {
            builder.connect(
                proof.public_inputs[REWARD_CLAIM_BATCH_STATEMENT_LEN + 4 + 4 * index + limb],
                cap.elements[limb],
            );
        }
    }
    let batch_count = proof.public_inputs[0];
    builder.range_check(batch_count, 6);
    let maximum_count = builder.constant(F::from_canonical_usize(BRIDGE_CLAIM_CAPACITY));
    builder.ensure_is_less_than_or_equal(6, batch_count, maximum_count);
    let end_checkpoint_id = builder.add_virtual_target();
    builder.range_check(end_checkpoint_id, 32);
    let mut claims = [[[builder.zero_u32(); 8]; BRIDGE_REWARD_CLAIM_WORDS]; BRIDGE_CLAIM_CAPACITY];
    let mut indices = Vec::new();
    let mut anchors = Vec::new();
    let end_checkpoint_root = builder.add_virtual_hash();
    for slot in 0..BRIDGE_CLAIM_CAPACITY {
        let slot_target = builder.constant(F::from_canonical_usize(slot));
        let active = active_flag(&mut builder, slot_target, batch_count);
        let index = builder.add_virtual_target();
        builder.range_check(index, 6);
        let inactive = builder.not(active);
        connect_if(&mut builder, inactive, index, zero);
        let index_bound = builder.select(active, batch_count, one);
        builder.ensure_is_less_than(6, index, index_bound);
        for earlier in &indices {
            let same = builder.is_equal(index, *earlier);
            let duplicate = builder.and(active, same);
            builder.connect(duplicate.target, zero);
        }
        let mut selected = vec![builder.zero(); REWARD_ROOT_STATEMENT_LEN];
        for statement_slot in 0..BRIDGE_CLAIM_CAPACITY {
            let start = 1 + statement_slot * REWARD_ROOT_STATEMENT_LEN;
            let statement_slot = builder.constant(F::from_canonical_usize(statement_slot));
            let matches = builder.is_equal(index, statement_slot);
            for field in 0..REWARD_ROOT_STATEMENT_LEN {
                selected[field] = builder.select(matches, proof.public_inputs[start + field], selected[field]);
            }
        }
        let anchor = AnchorToEndTarget::add_virtual(&mut builder);
        let internal_end = builder.select(active, end_checkpoint_id, zero);
        builder.connect(anchor.end_checkpoint_id, internal_end);
        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let internal_leaf = HashOutTarget { elements: std::array::from_fn(|limb| builder.select(active, anchor.historical.current_value.elements[limb], zero_hash.elements[limb])) };
        builder.connect_hashes(anchor.historical.current_value, internal_leaf);
        for (level, sibling) in anchor.historical.siblings.iter().enumerate() {
            let empty = builder.constant_hash(<PoseidonHash as MerkleZeroHasher<HashOut<F>>>::get_zero_hash(level));
            let selected = HashOutTarget { elements: std::array::from_fn(|limb| builder.select(active, sibling.elements[limb], empty.elements[limb])) };
            builder.connect_hashes(*sibling, selected);
        }
        let anchor_root = HashOutTarget { elements: std::array::from_fn(|limb| selected[26 + limb]) };
        connect_hash_if(&mut builder, active, anchor.anchor_root, anchor_root);
        connect_hash_if(&mut builder, active, anchor.end_root, end_checkpoint_root);
        let kind = builder.constant(F::from_canonical_u32(KIND_REWARD));
        let chain = builder.constant(F::from_canonical_u32(u32::from(ethereum_index)));
        let contract = builder.constant(F::from_canonical_u64(BRIDGE_REWARD_CONTRACT_ID));
        for (word, value, bits) in [(0, kind, 8), (1, chain, 8), (2, selected[0], 32), (3, contract, 24)] {
            let value = bounded(&mut builder, value, bits);
            claims[slot][word] = select_word(&mut builder, active, value);
        }
        for root in 0..4 {
            let old_root = builder.select(active, selected[9 + root], zero);
            let new_root = builder.select(active, selected[13 + root], zero);
            claims[slot][4 + root] = canonical_root_word(&mut builder, old_root);
            claims[slot][8 + root] = canonical_root_word(&mut builder, new_root);
        }
        let claim_count = bounded(&mut builder, selected[17], 32);
        claims[slot][12] = select_word(&mut builder, active, claim_count);
        claims[slot][13] = reward_word(&mut builder, active, &selected, 1, true);
        claims[slot][14] = reward_word(&mut builder, active, &selected, 18, true);
        indices.push(index);
        anchors.push(anchor);
    }
    let mut statement = vec![batch_count, end_checkpoint_id];
    statement.extend(end_checkpoint_root.elements);
    for claim in &claims {
        for word in claim { statement.extend(word_targets(*word)); }
    }
    assert_eq!(statement.len(), BRIDGE_REWARD_CLAIM_STATEMENT_LEN);
    builder.register_public_inputs(&statement);
    while builder.num_gates() < 1 << BRIDGE_CLAIM_DEGREE_BITS {
        builder.add_gate(plonky2::gates::noop::NoopGate, vec![]);
    }
    let circuit_data = builder.build::<C>();
    BridgeRewardClaimCircuit {
        targets: BridgeRewardClaimTargets {
            count: batch_count, end_checkpoint_id, end_checkpoint_root, claims,
            indices: indices.try_into().unwrap(), anchors: anchors.try_into().unwrap(), batch_proof: proof,
        },
        fingerprint: parth_core::pgoldilocks::QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only)),
        circuit_data,
    }
}

impl BridgeWithdrawalClaimCircuit {
    pub fn new(policies: Vec<BridgeTokenPolicy>) -> anyhow::Result<Self> {
        anyhow::ensure!(!policies.is_empty(), "at least one token policy is required");
        anyhow::ensure!(policies.len() <= 255, "token policy collection exceeds the u8 selector bound");
        for (position, policy) in policies.iter().enumerate() {
            anyhow::ensure!(policy.token_contract_id < 1 << 24, "token contract identifier exceeds u24");
            anyhow::ensure!(policy.token_address[..3].iter().all(|limb| *limb == 0), "token address exceeds 160 bits");
            anyhow::ensure!(policy.approved_leaf.state_tree_height == F::from_canonical_usize(STATE_HEIGHT), "approved leaf state height must be 32");
            anyhow::ensure!(policy.capacity > 0, "token map capacity must be positive");
            anyhow::ensure!(policy.map_base.checked_add(policy.capacity).is_some(), "token map base plus capacity overflows u32");
            if position > 0 {
                let earlier = &policies[position - 1];
                anyhow::ensure!(
                    (earlier.chain_index, earlier.token_contract_id) < (policy.chain_index, policy.token_contract_id),
                    "token policies must be sorted and unique by (chain_index, token_contract_id)",
                );
            }
        }
        Ok(build_withdrawal(&policies))
    }

    pub fn policies(&self) -> &[BridgeTokenPolicy] { &self.policies }

    pub fn prove(&self, input: &BridgeWithdrawalClaimInput) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.circuit_data.prove(self.set_witness(input)?)
    }

    pub fn set_witness(&self, input: &BridgeWithdrawalClaimInput) -> anyhow::Result<PartialWitness<F>> {
        anyhow::ensure!(input.claims.len() <= BRIDGE_CLAIM_CAPACITY, "too many withdrawal claims");
        let mut witness = PartialWitness::new();
        witness.set_target(self.targets.count, F::from_canonical_usize(input.claims.len()))?;
        witness.set_target(self.targets.end_checkpoint_id, F::from_canonical_u32(input.end_checkpoint_id))?;
        witness.set_hash_target(self.targets.end_checkpoint_root, input.end_checkpoint_root)?;
        witness.set_hash_target(self.targets.end_gusr, input.end_gusr)?;
        witness.set_hash_target(self.targets.end_gcon, input.end_gcon)?;
        let zero_user = UserContractState {
            checkpoint_tree_root: QHashOut::ZERO,
            user_leaf: PsyUserLeaf::default(),
            start_contract_state_root: QHashOut::ZERO,
            contract_id: F::ZERO,
            checkpoint_id: F::ZERO,
        };
        let zero_imt = IMTContractStateLeaf { key: QHashOut::ZERO, value: QHashOut::ZERO, next_key: QHashOut::ZERO, next_index: F::ZERO };
        let zero_imt_hash = zero_imt.qfhash::<PoseidonHash>().0;
        let zero_user_hash = zero_user.user_leaf.alghash::<PoseidonHash>().0;
        let zero_user_siblings = [HashOut::ZERO; GLOBAL_USER_TREE_HEIGHT as usize];
        let zero_contract_siblings = [HashOut::ZERO; GLOBAL_CONTRACT_TREE_HEIGHT as usize];
        let zero_state_siblings = [HashOut::ZERO; STATE_HEIGHT];
        for slot in 0..BRIDGE_CLAIM_CAPACITY {
            if let Some(claim) = input.claims.get(slot) {
                anyhow::ensure!((claim.policy_ordinal as usize) < self.policies.len(), "policy ordinal out of range");
                let policy = &self.policies[claim.policy_ordinal as usize];
                anyhow::ensure!(claim.token_address == policy.token_address, "token address mismatch");
                witness.set_target(self.targets.ordinals[slot], F::from_canonical_u8(claim.policy_ordinal))?;
                self.targets.users[slot].set_witness(&mut witness, &claim.user_contract)?;
                self.targets.contracts[slot].set_witness(&mut witness, &policy.approved_leaf)?;
                self.targets.user_paths[slot].set_witness_generic_ho(&mut witness, claim.user_contract.user_leaf.user_id, claim.user_contract.user_leaf.alghash::<PoseidonHash>().0, &claim.user_siblings)?;
                self.targets.contract_paths[slot].set_witness_generic_ho(&mut witness, claim.user_contract.contract_id, claim.user_contract.start_contract_state_root.0, &claim.contract_siblings)?;
                self.targets.global_contract_paths[slot].set_witness_generic_ho(&mut witness, claim.user_contract.contract_id, contract_leaf_hash(&policy.approved_leaf), &claim.global_contract_siblings)?;
                self.targets.members[slot].set_witness(&mut witness, &claim.member)?;
                self.targets.member_paths[slot].set_witness_generic_ho(&mut witness, F::from_canonical_u32(claim.member_index), claim.member.qfhash::<PoseidonHash>().0, &claim.member_siblings)?;
                self.targets.sentinels[slot].set_witness(&mut witness, &claim.sentinel)?;
                self.targets.sentinel_paths[slot].set_witness_generic_ho(&mut witness, F::from_canonical_u32(policy.map_base), claim.sentinel.qfhash::<PoseidonHash>().0, &claim.sentinel_siblings)?;
                let payment = &self.targets.payments[slot];
                for word in 0..8 {
                    witness.set_u32_target(payment.recipient[word], claim.recipient[word])?;
                    witness.set_u32_target(payment.amount[word], claim.amount[word])?;
                    witness.set_u32_target(payment.nonce[word], claim.nonce[word])?;
                }
            } else {
                witness.set_target(self.targets.ordinals[slot], F::ZERO)?;
                self.targets.users[slot].set_witness(&mut witness, &zero_user)?;
                self.targets.contracts[slot].set_witness(&mut witness, &self.policies[0].approved_leaf)?;
                self.targets.user_paths[slot].set_witness_generic_ho(&mut witness, F::ZERO, zero_user_hash, &zero_user_siblings)?;
                self.targets.contract_paths[slot].set_witness_generic_ho(&mut witness, F::ZERO, HashOut::ZERO, &zero_contract_siblings)?;
                self.targets.global_contract_paths[slot].set_witness_generic_ho(&mut witness, F::ZERO, contract_leaf_hash(&self.policies[0].approved_leaf), &zero_contract_siblings)?;
                self.targets.members[slot].set_witness(&mut witness, &zero_imt)?;
                self.targets.member_paths[slot].set_witness_generic_ho(&mut witness, F::ZERO, zero_imt_hash, &zero_state_siblings)?;
                self.targets.sentinels[slot].set_witness(&mut witness, &zero_imt)?;
                self.targets.sentinel_paths[slot].set_witness_generic_ho(&mut witness, F::ZERO, zero_imt_hash, &zero_state_siblings)?;
                let payment = &self.targets.payments[slot];
                for word in 0..8 {
                    witness.set_u32_target(payment.recipient[word], 0)?;
                    witness.set_u32_target(payment.amount[word], 0)?;
                    witness.set_u32_target(payment.nonce[word], 0)?;
                }
            }
        }
        Ok(witness)
    }
}

impl BridgeRewardClaimCircuit {
    pub fn new(batch_common: &CommonCircuitData<F, D>, batch_verifier: &VerifierOnlyCircuitData<C, D>, ethereum_index: u8) -> Self {
        build_reward(batch_common, batch_verifier, ethereum_index)
    }

    pub fn prove(&self, input: &BridgeRewardClaimInput) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.circuit_data.prove(self.set_witness(input)?)
    }

    pub fn set_witness(&self, input: &BridgeRewardClaimInput) -> anyhow::Result<PartialWitness<F>> {
        anyhow::ensure!(input.batch_proof.public_inputs.len() >= REWARD_CLAIM_BATCH_STATEMENT_LEN, "batch statement missing");
        let count = input.batch_proof.public_inputs[0].to_canonical_u64() as usize;
        anyhow::ensure!(input.claims.len() == count, "claim count must equal batch count");
        anyhow::ensure!(count <= BRIDGE_CLAIM_CAPACITY, "too many reward claims");
        let mut witness = PartialWitness::new();
        witness.set_target(self.targets.end_checkpoint_id, F::from_canonical_u32(input.end_checkpoint_id))?;
        witness.set_hash_target(self.targets.end_checkpoint_root, input.end_checkpoint_root)?;
        witness.set_proof_with_pis_target(&self.targets.batch_proof, &input.batch_proof)?;
        for slot in 0..BRIDGE_CLAIM_CAPACITY {
            if let Some(claim) = input.claims.get(slot) {
                witness.set_target(self.targets.indices[slot], F::from_canonical_u32(claim.statement_index))?;
                self.targets.anchors[slot].set_witness(&mut witness, F::from_canonical_u32(claim.anchor_checkpoint_id), F::from_canonical_u32(input.end_checkpoint_id), claim.anchor_leaf, &claim.anchor_siblings)?;
            } else {
                witness.set_target(self.targets.indices[slot], F::ZERO)?;
                self.targets.anchors[slot].set_witness_empty_tree(&mut witness)?;
            }
        }
        Ok(witness)
    }
}

impl QStandardCircuit<C, D> for BridgeWithdrawalClaimCircuit {
    fn get_fingerprint(&self) -> parth_core::pgoldilocks::QHashOut<F> { self.fingerprint }
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> { &self.circuit_data.verifier_only }
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<F, D> { &self.circuit_data.common }
}

impl QStandardCircuit<C, D> for BridgeRewardClaimCircuit {
    fn get_fingerprint(&self) -> parth_core::pgoldilocks::QHashOut<F> { self.fingerprint }
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> { &self.circuit_data.verifier_only }
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<F, D> { &self.circuit_data.common }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use psy_crypto::hash::traits::qhashable::QFieldHashable;
    use psy_client_data::qdata::checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf};
    use psy_common_circuit::circuits::zk_signature3::core::PsyBasicZKSignatureCircuit;
    use crate::bridge::{
        circuits::{reward_chain::*, reward_claim_batch::*},
        gadgets::reward_nullifier::RewardNullifierSourceWitness,
    };

    type Leaves = BTreeMap<u64, HashOut<F>>;
    fn zero_hash(level: usize) -> HashOut<F> { <PoseidonHash as MerkleZeroHasher<HashOut<F>>>::get_zero_hash(level) }
    fn sparse_path<const HEIGHT: usize>(leaves: &Leaves, index: u64) -> ([HashOut<F>; HEIGHT], HashOut<F>) {
        let mut layer = leaves.clone();
        let mut siblings = [HashOut::ZERO; HEIGHT];
        let mut cursor = index;
        for level in 0..HEIGHT {
            siblings[level] = layer.get(&(cursor ^ 1)).copied().unwrap_or_else(|| zero_hash(level));
            let mut parents = BTreeMap::new();
            for position in layer.keys().copied().chain([cursor]) {
                let parent = position >> 1;
                let left = parent << 1;
                let left_hash = layer.get(&left).copied().unwrap_or_else(|| zero_hash(level));
                let right_hash = layer.get(&(left + 1)).copied().unwrap_or_else(|| zero_hash(level));
                parents.insert(parent, PoseidonHash::two_to_one(left_hash, right_hash));
            }
            layer = parents;
            cursor >>= 1;
        }
        (siblings, layer.get(&0).copied().unwrap_or_else(|| zero_hash(HEIGHT)))
    }
    fn tagged(left: HashOut<F>, right: HashOut<F>, tag: HashOut<F>) -> HashOut<F> { PoseidonHash::two_to_one(PoseidonHash::two_to_one(left, right), tag) }
    fn reward_tip(user_id: u32) -> (RewardSegmentCircuit, RewardMergeCircuit, RewardRootCircuit, RewardRootProof, HashOut<F>, [HashOut<F>; 32]) {
        use parth_core::pgoldilocks::QHashOut;
        let segment = RewardSegmentCircuit::new();
        let merge = RewardMergeCircuit::new(&segment);
        let root = RewardRootCircuit::new(&merge);
        let preimage = QHashOut::from_values(u64::from(user_id), 1, 0, 0);
        let tag = PoseidonHash::two_to_one(preimage.0, preimage.0);
        let mut levels = vec![(0..64).map(|index| tagged(QHashOut::from_values(index, 0, 0, 0).0, HashOut::ZERO, tag)).collect::<Vec<_>>()];
        for level in 0..6 { levels.push(levels[level].chunks_exact(2).map(|pair| tagged(pair[0], pair[1], HashOut::ZERO)).collect()); }
        let mut checkpoint = PsyCheckpointLeaf::default();
        checkpoint.stats.pm_rewards_commitment.gutas_root.0 = levels[6][0];
        checkpoint.stats.pm_jobs_completed.gutas_completed = F::from_canonical_u32(64);
        checkpoint.stats.guta_fees_collected = F::from_canonical_u32(640);
        let hash = checkpoint.qfhash::<PoseidonHash>().0;
        let private_key = psy_client_common::data::qhashout::QHashOut::from_values(17, 23, 31, 47);
        let param = psy_ups_circuit::signature::software_defined::get_sdc_public_key_param(&private_key);
        let identity = PsyBasicZKSignatureCircuit::<C, D>::new().fingerprint.0;
        let user_leaf = PsyUserLeaf {
            user_id: F::from_canonical_u32(user_id),
            public_key: psy_client_common::data::qhashout::QHashOut(PoseidonHash::two_to_one(identity, param.0)),
            ..PsyUserLeaf::default()
        };
        let users = Leaves::from([(u64::from(user_id), user_leaf.alghash::<PoseidonHash>().0)]);
        let (user_siblings, user_root) = sparse_path::<{ GLOBAL_USER_TREE_HEIGHT as usize }>(&users, u64::from(user_id));
        let global_roots = PsyCheckpointGlobalStateRoots { user_tree_root: psy_client_common::data::qhashout::QHashOut(user_root), ..Default::default() };
        let mut anchor_leaf = PsyCheckpointLeaf::default();
        anchor_leaf.global_chain_root = global_roots.qfhash::<PoseidonHash>();
        let checkpoints = Leaves::from([(1024, hash), (1025, anchor_leaf.qfhash::<PoseidonHash>().0)]);
        let source = 1024u32;
        let old_inner_root = zero_hash(22);
        let outer_siblings = std::array::from_fn(|level| zero_hash(22 + level));
        let old_nullifier_root = zero_hash(54);
        let inner_siblings = vec![sparse_path::<22>(&Leaves::new(), 63).0];
        let (checkpoint_siblings, checkpoint_tree_root) = sparse_path::<32>(&checkpoints, source as u64);
        let segment_proof = segment.prove(&RewardSegmentWitness {
            user_id, anchor_checkpoint_id: 1025, checkpoint_tree_root, old_nullifier_root,
            source: RewardSegmentSourceWitness {
                source_checkpoint_id: source, checkpoint_leaf: checkpoint, checkpoint_siblings,
                amount_limbs: [10, 0], nullifier: RewardNullifierSourceWitness { old_inner_root, outer_siblings, inner_siblings },
                jobs: vec![AuthenticatedJobWitness {
                    source_checkpoint_id: source, height: 6, path_index: 0,
                    tag: RewardTagWitness { tag_preimage: preimage, leaf_left: QHashOut::from_values(0, 0, 0, 0), leaf_right: QHashOut::ZERO, leaf_tag: QHashOut(tag), siblings: std::array::from_fn(|level| if level < 6 { QHashOut(levels[level][1]) } else { QHashOut::ZERO }), parent_tags: [QHashOut::ZERO; 21] },
                }],
            },
        }).unwrap();
        let merge_proof = merge.prove(&RewardMergeWitness::Leaf { segment: segment_proof }).unwrap();
        let (anchor_siblings, _anchor_root) = sparse_path::<32>(&checkpoints, 1025);
        let root_proof = root.prove(&RewardRootWitness {
            recipient: [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0, 0, 0],
            anchor_checkpoint_id: 1025, anchor_leaf, anchor_siblings, global_roots,
            user_leaf, user_siblings, private_key: private_key.0, merge_proof,
        }).unwrap();
        (segment, merge, root, root_proof, anchor_leaf.qfhash::<PoseidonHash>().0, anchor_siblings)
    }

    #[test]
    fn withdrawal_authenticates_one_counted_imt_and_rejects_targeted_changes() {
        let policy = BridgeTokenPolicy {
            chain_index: 1, token_contract_id: 7, token_address: [0, 0, 0, 4, 5, 6, 7, 8],
            approved_leaf: PsyContractLeaf { state_tree_height: F::from_canonical_usize(STATE_HEIGHT), ..PsyContractLeaf::default() },
            map_base: 8, capacity: 4,
        };
        let mut other_policy = policy.clone();
        other_policy.chain_index += 1;
        let circuit = BridgeWithdrawalClaimCircuit::new(vec![policy.clone(), other_policy]).unwrap();
        let recipient = [0, 0, 0, 6, 5, 4, 3, 2];
        let amount = [0, 0, 0, 0, 0, 0, 1, 1];
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let nonce_hash = PoseidonHash::hash_no_pad(&nonce.map(F::from_canonical_u32));
        let mut key_inputs = vec![F::from_canonical_u64(WITHDRAWAL_NAMESPACE)];
        key_inputs.extend(nonce_hash.elements);
        let key = QHashOut(PoseidonHash::hash_no_pad(&key_inputs));
        let mut value_inputs = vec![F::from_canonical_u32(11)];
        for word in [recipient, policy.token_address, amount, nonce] { value_inputs.extend(word.map(F::from_canonical_u32)); }
        value_inputs.push(F::from_canonical_u8(policy.chain_index));
        let value = QHashOut(PoseidonHash::hash_no_pad(&value_inputs));
        let next_key = key;
        let sentinel = IMTContractStateLeaf { key: QHashOut::ZERO, value: QHashOut::from_values(1, 0, 0, 0), next_key, next_index: F::from_canonical_u32(policy.map_base + 1) };
        let member = IMTContractStateLeaf { key, value, next_key: QHashOut::ZERO, next_index: F::ZERO };
        let mut state = BTreeMap::new();
        state.insert(policy.map_base as u64, sentinel.qfhash::<PoseidonHash>().0);
        state.insert((policy.map_base + 1) as u64, member.qfhash::<PoseidonHash>().0);
        let (sentinel_siblings, state_root) = sparse_path::<STATE_HEIGHT>(&state, policy.map_base as u64);
        let (member_siblings, member_root) = sparse_path::<STATE_HEIGHT>(&state, (policy.map_base + 1) as u64);
        assert_eq!(state_root, member_root);
        let contracts = Leaves::from([(u64::from(policy.token_contract_id), state_root)]);
        let (contract_siblings, contract_root) = sparse_path::<{ GLOBAL_CONTRACT_TREE_HEIGHT as usize }>(&contracts, u64::from(policy.token_contract_id));
        let definitions = Leaves::from([(u64::from(policy.token_contract_id), contract_leaf_hash(&policy.approved_leaf))]);
        let (global_contract_siblings, gcon) = sparse_path::<{ GLOBAL_CONTRACT_TREE_HEIGHT as usize }>(&definitions, u64::from(policy.token_contract_id));
        let user_leaf = PsyUserLeaf { user_id: F::from_canonical_u32(11), user_state_tree_root: QHashOut(contract_root), ..PsyUserLeaf::default() };
        let mut users = BTreeMap::new();
        users.insert(11, user_leaf.alghash::<PoseidonHash>().0);
        let (user_siblings, gusr) = sparse_path::<{ GLOBAL_USER_TREE_HEIGHT as usize }>(&users, 11);
        let input = BridgeWithdrawalClaimInput {
            end_checkpoint_id: 12, end_checkpoint_root: HashOut::from_partial(&[F::from_canonical_u64(12)]), end_gusr: gusr, end_gcon: gcon,
            claims: vec![BridgeWithdrawalClaimWitness {
                policy_ordinal: 0,
                user_contract: UserContractState { checkpoint_tree_root: QHashOut::default(), user_leaf, start_contract_state_root: QHashOut(state_root), contract_id: F::from_canonical_u32(policy.token_contract_id), checkpoint_id: F::from_canonical_u8(policy.chain_index) },
                user_siblings, contract_siblings, global_contract_siblings, member_index: policy.map_base + 1, member, member_siblings, sentinel, sentinel_siblings, recipient, token_address: policy.token_address, amount, nonce,
            }],
        };
        let output = circuit.prove(&input).unwrap();
        assert_eq!(output.public_inputs[14 + 2 * 8 + 7], F::from_canonical_u32(11));
        assert_eq!(output.public_inputs[14 + 3 * 8 + 7], F::from_canonical_u32(7));
        let mutations: [fn(&mut BridgeWithdrawalClaimInput); 12] = [
            |bad| bad.end_gusr.elements[0] += F::ONE,
            |bad| bad.end_gcon.elements[0] += F::ONE,
            |bad| bad.claims[0].member.key.0.elements[0] += F::ONE,
            |bad| bad.claims[0].sentinel.value.0.elements[0] += F::ONE,
            |bad| bad.claims.push(bad.claims[0].clone()),
            |bad| bad.claims[0].member_index = 8,
            |bad| bad.claims[0].nonce[7] += 1,
            |bad| { bad.claims[0].amount[7] = 0; bad.claims[0].recipient[7] += 1; },
            |bad| bad.claims[0].contract_siblings[0].elements[0] += F::ONE,
            |bad| bad.claims[0].global_contract_siblings[0].elements[0] += F::ONE,
            |bad| bad.claims[0].policy_ordinal = 1,
            |bad| bad.claims[0].user_contract.start_contract_state_root.0.elements[0] += F::ONE,
        ];
        for (index, mutation) in mutations.iter().enumerate() {
            let mut bad = input.clone();
            mutation(&mut bad);
            assert!(circuit.prove(&bad).is_err(), "mutation {index}");
        }
        let mut bad = circuit.set_witness(&input).unwrap();
        bad.target_values.insert(circuit.targets.ordinals[0], F::ONE);
        assert!(circuit.circuit_data.prove(bad).is_err(), "ordinal constraint must reject bypassing host checks");
        let mut bad = circuit.set_witness(&input).unwrap();
        bad.target_values.insert(circuit.targets.payments[1].recipient[7].0, F::ONE);
        assert!(circuit.circuit_data.prove(bad).is_err(), "inactive payment padding must be zero");
        for field in 0..6 {
            let mut other_leaf = policy.approved_leaf;
            match field {
                0..=3 => other_leaf.state_layout_root.0.elements[field] += F::ONE,
                4 => other_leaf.state_layout_field_count += F::ONE,
                _ => other_leaf.state_layout_slot_count += F::ONE,
            }
            let definitions = Leaves::from([(u64::from(policy.token_contract_id), contract_leaf_hash(&other_leaf))]);
            let (siblings, root) = sparse_path::<{ GLOBAL_CONTRACT_TREE_HEIGHT as usize }>(&definitions, u64::from(policy.token_contract_id));
            let mut bad = input.clone();
            bad.end_gcon = root;
            bad.claims[0].global_contract_siblings = siblings;
            assert!(circuit.prove(&bad).is_err(), "full approved layout field {field} must be bound");
        }
        let old_contracts = Leaves::from([(u64::from(policy.token_contract_id), contract_leaf_hash(&policy.approved_leaf))]);
        let (siblings, root) = sparse_path::<{ GLOBAL_CONTRACT_TREE_HEIGHT as usize }>(&old_contracts, u64::from(policy.token_contract_id));
        let mut bad = input.clone();
        bad.claims[0].contract_siblings = siblings;
        bad.claims[0].user_contract.user_leaf.user_state_tree_root = QHashOut(root);
        let users = Leaves::from([(11, bad.claims[0].user_contract.user_leaf.alghash::<PoseidonHash>().0)]);
        let (siblings, root) = sparse_path::<{ GLOBAL_USER_TREE_HEIGHT as usize }>(&users, 11);
        bad.claims[0].user_siblings = siblings;
        bad.end_gusr = root;
        assert!(circuit.prove(&bad).is_err(), "UCON must authenticate raw CSTATE, not the approved contract leaf");
    }

    #[test]
    fn withdrawal_amount_is_positive_and_below_goldilocks_modulus() {
        let policy = BridgeTokenPolicy {
            chain_index: 1, token_contract_id: 7, token_address: [0, 0, 0, 4, 5, 6, 7, 8],
            approved_leaf: PsyContractLeaf { state_tree_height: F::from_canonical_usize(STATE_HEIGHT), ..PsyContractLeaf::default() },
            map_base: 8, capacity: 4,
        };
        let circuit = BridgeWithdrawalClaimCircuit::new(vec![policy.clone()]).unwrap();
        let recipient_limbs = [0, 0, 0, 6, 5, 4, 3, 2].map(F::from_canonical_u32);
        let nonce_limbs = [1, 2, 3, 4, 5, 6, 7, 8].map(F::from_canonical_u32);
        // The largest allowed amount, p - 1 = 0xffffffff_00000000, must prove and
        // reach the statement words unchanged.
        let mut maximum_amount = [F::ZERO; 8];
        maximum_amount[6] = F::from_canonical_u32(u32::MAX);
        let output = circuit.prove(&withdrawal_claim_with_payments(&policy, recipient_limbs, maximum_amount, nonce_limbs)).unwrap();
        assert_eq!(output.public_inputs[14 + 9 * 8 + 6], F::from_canonical_u32(u32::MAX));
        assert_eq!(output.public_inputs[14 + 9 * 8 + 7], F::ZERO);
        // The Goldilocks modulus itself must be rejected: limbs are consistent with
        // the burned record, so only the canonical amount gate can fail.
        let mut modulus_amount = maximum_amount;
        modulus_amount[7] = F::ONE;
        assert!(circuit.prove(&withdrawal_claim_with_payments(&policy, recipient_limbs, modulus_amount, nonce_limbs)).is_err(), "amount equal to the Goldilocks modulus must be rejected");
        // A low limb at 2^32 is not a u32. The burned record value is rebuilt around
        // the overwide field element, so only the limb range gate can fail.
        let mut overwide_amount = [F::ZERO; 8];
        overwide_amount[7] = F::from_canonical_u64(1 << 32);
        let overwide = withdrawal_claim_with_payments(&policy, recipient_limbs, overwide_amount, nonce_limbs);
        let mut witness = circuit.set_witness(&overwide).unwrap();
        witness.target_values.insert(circuit.targets.payments[0].amount[7].0, F::from_canonical_u64(1 << 32));
        assert!(circuit.circuit_data.prove(witness).is_err(), "overwide amount limb must be rejected");
    }

    #[test]
    fn withdrawal_recipient_and_nonce_limbs_are_canonical_with_zero_padding() {
        let policy = BridgeTokenPolicy {
            chain_index: 1, token_contract_id: 7, token_address: [0, 0, 0, 4, 5, 6, 7, 8],
            approved_leaf: PsyContractLeaf { state_tree_height: F::from_canonical_usize(STATE_HEIGHT), ..PsyContractLeaf::default() },
            map_base: 8, capacity: 4,
        };
        let circuit = BridgeWithdrawalClaimCircuit::new(vec![policy.clone()]).unwrap();
        let recipient_limbs = [0, 0, 0, 6, 5, 4, 3, 2].map(F::from_canonical_u32);
        let unit_amount = { let mut limbs = [F::ZERO; 8]; limbs[7] = F::ONE; limbs };
        // A full-width 256-bit nonce proves and reaches the statement unchanged.
        let full_nonce = [F::from_canonical_u32(u32::MAX); 8];
        let output = circuit.prove(&withdrawal_claim_with_payments(&policy, recipient_limbs, unit_amount, full_nonce)).unwrap();
        for limb in 0..3 { assert_eq!(output.public_inputs[14 + 8 * 8 + limb], F::ZERO, "recipient padding limb {limb}"); }
        assert_eq!(output.public_inputs[14 + 8 * 8 + 3], F::from_canonical_u32(6));
        for limb in 0..8 { assert_eq!(output.public_inputs[14 + 4 * 8 + limb], F::from_canonical_u32(u32::MAX), "nonce limb {limb}"); }
        // Recipient padding above the 160-bit address must be rejected.
        let mut padded_recipient = recipient_limbs;
        padded_recipient[2] = F::ONE;
        assert!(circuit.prove(&withdrawal_claim_with_payments(&policy, padded_recipient, unit_amount, full_nonce)).is_err(), "recipient padding above 160 bits must be zero");
        // A recipient limb wider than u32 must be rejected.
        let mut overwide_recipient = recipient_limbs;
        overwide_recipient[7] = F::from_canonical_u64(1 << 32);
        let input = withdrawal_claim_with_payments(&policy, overwide_recipient, unit_amount, full_nonce);
        let mut witness = circuit.set_witness(&input).unwrap();
        witness.target_values.insert(circuit.targets.payments[0].recipient[7].0, F::from_canonical_u64(1 << 32));
        assert!(circuit.circuit_data.prove(witness).is_err(), "overwide recipient limb must be rejected");
        // A nonce limb wider than u32 must be rejected.
        let mut overwide_nonce = full_nonce;
        overwide_nonce[3] = F::from_canonical_u64(1 << 32);
        let input = withdrawal_claim_with_payments(&policy, recipient_limbs, unit_amount, overwide_nonce);
        let mut witness = circuit.set_witness(&input).unwrap();
        witness.target_values.insert(circuit.targets.payments[0].nonce[3].0, F::from_canonical_u64(1 << 32));
        assert!(circuit.circuit_data.prove(witness).is_err(), "overwide nonce limb must be rejected");
    }

    /// One active withdrawal claim whose burned record key and value hashes are
    /// built around the exact payment limb field elements — the key exactly as
    /// withdrawal_key_value hashes the raw nonce targets — so payment-gate
    /// rejections are not masked by record membership mismatches. The truncated
    /// u32 limbs only drive the typed witness serialization; raw overrides then
    /// replace those target values before proving.
    fn withdrawal_claim_with_payments(
        policy: &BridgeTokenPolicy,
        recipient_limbs: [F; 8],
        amount_limbs: [F; 8],
        nonce_limbs: [F; 8],
    ) -> BridgeWithdrawalClaimInput {
        let recipient = recipient_limbs.map(|limb| limb.to_canonical_u64() as u32);
        let amount = amount_limbs.map(|limb| limb.to_canonical_u64() as u32);
        let nonce = nonce_limbs.map(|limb| limb.to_canonical_u64() as u32);
        let nonce_hash = PoseidonHash::hash_no_pad(&nonce_limbs);
        let mut key_inputs = vec![F::from_canonical_u64(WITHDRAWAL_NAMESPACE)];
        key_inputs.extend(nonce_hash.elements);
        let key = QHashOut(PoseidonHash::hash_no_pad(&key_inputs));
        let mut value_inputs = vec![F::from_canonical_u32(11)];
        for word in [recipient_limbs, policy.token_address.map(F::from_canonical_u32), amount_limbs, nonce_limbs] {
            value_inputs.extend(word);
        }
        value_inputs.push(F::from_canonical_u8(policy.chain_index));
        let value = QHashOut(PoseidonHash::hash_no_pad(&value_inputs));
        let sentinel = IMTContractStateLeaf { key: QHashOut::ZERO, value: QHashOut::from_values(1, 0, 0, 0), next_key: key, next_index: F::from_canonical_u32(policy.map_base + 1) };
        let member = IMTContractStateLeaf { key, value, next_key: QHashOut::ZERO, next_index: F::ZERO };
        let mut state = BTreeMap::new();
        state.insert(policy.map_base as u64, sentinel.qfhash::<PoseidonHash>().0);
        state.insert((policy.map_base + 1) as u64, member.qfhash::<PoseidonHash>().0);
        let (sentinel_siblings, state_root) = sparse_path::<STATE_HEIGHT>(&state, policy.map_base as u64);
        let (member_siblings, member_root) = sparse_path::<STATE_HEIGHT>(&state, (policy.map_base + 1) as u64);
        assert_eq!(state_root, member_root);
        let contracts = Leaves::from([(u64::from(policy.token_contract_id), state_root)]);
        let (contract_siblings, contract_root) = sparse_path::<{ GLOBAL_CONTRACT_TREE_HEIGHT as usize }>(&contracts, u64::from(policy.token_contract_id));
        let definitions = Leaves::from([(u64::from(policy.token_contract_id), contract_leaf_hash(&policy.approved_leaf))]);
        let (global_contract_siblings, gcon) = sparse_path::<{ GLOBAL_CONTRACT_TREE_HEIGHT as usize }>(&definitions, u64::from(policy.token_contract_id));
        let user_leaf = PsyUserLeaf { user_id: F::from_canonical_u32(11), user_state_tree_root: QHashOut(contract_root), ..PsyUserLeaf::default() };
        let users = Leaves::from([(11, user_leaf.alghash::<PoseidonHash>().0)]);
        let (user_siblings, gusr) = sparse_path::<{ GLOBAL_USER_TREE_HEIGHT as usize }>(&users, 11);
        BridgeWithdrawalClaimInput {
            end_checkpoint_id: 12, end_checkpoint_root: HashOut::from_partial(&[F::from_canonical_u64(12)]), end_gusr: gusr, end_gcon: gcon,
            claims: vec![BridgeWithdrawalClaimWitness {
                policy_ordinal: 0,
                user_contract: UserContractState { checkpoint_tree_root: QHashOut::default(), user_leaf, start_contract_state_root: QHashOut(state_root), contract_id: F::from_canonical_u32(policy.token_contract_id), checkpoint_id: F::from_canonical_u8(policy.chain_index) },
                user_siblings, contract_siblings, global_contract_siblings, member_index: policy.map_base + 1, member, member_siblings, sentinel, sentinel_siblings, recipient, token_address: policy.token_address, amount, nonce,
            }],
        }
    }

    #[test]
    fn reward_uses_real_batch_and_rejects_index_and_anchor_changes() {
        let (_segment, _merge, root, root_proof, anchor_leaf, anchor_siblings) = reward_tip(7);
        let end_checkpoint_root = HashOut { elements: root_proof.public_inputs[26..30].try_into().unwrap() };
        let batch = RewardClaimBatchCircuit::new(root.get_common_circuit_data_ref(), root.get_verifier_config_ref());
        let statement: [F; REWARD_ROOT_STATEMENT_LEN] = root_proof.public_inputs[..REWARD_ROOT_STATEMENT_LEN].try_into().unwrap();
        let batch_proof = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Leaf, statements: vec![statement], tip: Some(root_proof), children: None }).unwrap();
        let claim = BridgeRewardClaimCircuit::new(batch.get_common_circuit_data_ref(), batch.get_verifier_config_ref(), 0);
        let input = BridgeRewardClaimInput { end_checkpoint_id: 1025, end_checkpoint_root, batch_proof, claims: vec![BridgeRewardClaimWitness { statement_index: 0, anchor_checkpoint_id: 1025, anchor_leaf, anchor_siblings }] };
        claim.prove(&input).unwrap();
        let mut bad = input.clone();
        bad.claims[0].statement_index = 1;
        assert!(claim.prove(&bad).is_err());
        bad = input.clone();
        bad.claims[0].anchor_siblings[0].elements[0] += F::ONE;
        assert!(claim.prove(&bad).is_err());
        bad = input.clone();
        bad.end_checkpoint_root.elements[0] += F::ONE;
        assert!(claim.prove(&bad).is_err(), "active anchor must bind the supplied endpoint root");
    }
    #[test]
    fn reward_claim_binds_statement_words_and_rejects_foreign_batch() {
        let (_segment, _merge, root, root_proof, anchor_leaf, anchor_siblings) = reward_tip(7);
        let recipient = [0x01020304u32, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0, 0, 0];
        let end_checkpoint_root = HashOut { elements: root_proof.public_inputs[26..30].try_into().unwrap() };
        let batch = RewardClaimBatchCircuit::new(root.get_common_circuit_data_ref(), root.get_verifier_config_ref());
        let statement: [F; REWARD_ROOT_STATEMENT_LEN] = root_proof.public_inputs[..REWARD_ROOT_STATEMENT_LEN].try_into().unwrap();
        let batch_proof = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Leaf, statements: vec![statement], tip: Some(root_proof), children: None }).unwrap();
        let claim = BridgeRewardClaimCircuit::new(batch.get_common_circuit_data_ref(), batch.get_verifier_config_ref(), 0);
        let input = BridgeRewardClaimInput { end_checkpoint_id: 1025, end_checkpoint_root, batch_proof: batch_proof.clone(), claims: vec![BridgeRewardClaimWitness { statement_index: 0, anchor_checkpoint_id: 1025, anchor_leaf, anchor_siblings }] };
        let output = claim.prove(&input).unwrap();
        let word = |word: usize, limb: usize| output.public_inputs[6 + word * 8 + limb];
        for limb in 0..7 { assert_eq!(word(0, limb), F::ZERO, "kind limb {limb}"); }
        assert_eq!(word(0, 7), F::from_canonical_u32(KIND_REWARD));
        for limb in 0..8 { assert_eq!(word(13, limb), F::from_canonical_u32(recipient[7 - limb]), "recipient limb {limb}"); }
        for limb in 0..7 { assert_eq!(word(14, limb), F::ZERO, "amount limb {limb}"); }
        assert_eq!(word(14, 7), F::from_canonical_u32(10));
        for (word_index, field) in (4..8).zip(9..13).chain((8..12).zip(13..17)) {
            let value = statement[field].to_canonical_u64();
            assert_eq!(word(word_index, 6), F::from_canonical_u32((value >> 32) as u32), "root word {word_index} high");
            assert_eq!(word(word_index, 7), F::from_canonical_u32(value as u32), "root word {word_index} low");
        }
        claim.circuit_data.verify(output).unwrap();

        let mut foreign_builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let marker = foreign_builder.add_virtual_target();
        let marker_value = foreign_builder.constant(F::from_canonical_u64(0xF001));
        foreign_builder.connect(marker, marker_value);
        let foreign_statement: [Target; REWARD_ROOT_STATEMENT_LEN] = std::array::from_fn(|_| foreign_builder.add_virtual_target());
        foreign_builder.register_public_inputs(&foreign_statement);
        let foreign_root = foreign_builder.build::<C>();
        assert_ne!(get_circuit_fingerprint_generic(&foreign_root.verifier_only), root.get_fingerprint().0, "foreign root verifier must differ");
        let foreign_batch = RewardClaimBatchCircuit::new(&foreign_root.common, &foreign_root.verifier_only);
        assert_ne!(foreign_batch.get_fingerprint(), batch.get_fingerprint(), "foreign batch verifier must differ");
        let foreign_batch_proof = foreign_batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Empty, statements: Vec::new(), tip: None, children: None }).unwrap();
        foreign_batch.circuit_data.verify(foreign_batch_proof.clone()).unwrap();
        let mut foreign = input;
        foreign.claims.clear();
        foreign.batch_proof = foreign_batch_proof;
        assert!(claim.prove(&foreign).is_err(), "a batch proof from another verifier was accepted");
    }
    #[test]
    fn empty_reward_batch_preserves_nonempty_endpoint_and_zeroed_claims() {
        let (_segment, _merge, root, root_proof, _, _) = reward_tip(7);
        let end_checkpoint_root = HashOut { elements: root_proof.public_inputs[26..30].try_into().unwrap() };
        assert_ne!(end_checkpoint_root, zero_hash(CHECKPOINT_TREE_HEIGHT as usize));
        let batch = RewardClaimBatchCircuit::new(root.get_common_circuit_data_ref(), root.get_verifier_config_ref());
        let batch_proof = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Empty, statements: Vec::new(), tip: None, children: None }).unwrap();
        let claim = BridgeRewardClaimCircuit::new(batch.get_common_circuit_data_ref(), batch.get_verifier_config_ref(), 0);
        let input = BridgeRewardClaimInput { end_checkpoint_id: 1025, end_checkpoint_root, batch_proof, claims: Vec::new() };
        let output = claim.prove(&input).unwrap();
        assert_eq!(output.public_inputs[0], F::ZERO);
        assert_eq!(&output.public_inputs[2..6], &end_checkpoint_root.elements);
        for slot in 0..BRIDGE_CLAIM_CAPACITY {
            for word in 0..BRIDGE_REWARD_CLAIM_WORDS {
                for limb in 0..8 {
                    let position = 6 + slot * BRIDGE_REWARD_CLAIM_WORDS * 8 + word * 8 + limb;
                    assert_eq!(output.public_inputs[position], F::ZERO, "slot {slot} word {word} limb {limb}");
                }
            }
        }
    }

    #[test]
    fn reward_consumer_rejects_same_family_decoy_suffix() {
        let (_segment, _merge, root, root_proof, anchor_leaf, anchor_siblings) = reward_tip(7);
        let batch = RewardClaimBatchCircuit::new(root.get_common_circuit_data_ref(), root.get_verifier_config_ref());
        let statement: [F; REWARD_ROOT_STATEMENT_LEN] = root_proof.public_inputs[..REWARD_ROOT_STATEMENT_LEN].try_into().unwrap();
        let end_checkpoint_root = HashOut { elements: root_proof.public_inputs[26..30].try_into().unwrap() };
        let empty = RewardClaimBatchWitness { mode: RewardClaimBatchMode::Empty, statements: Vec::new(), tip: None, children: None };
        let leaf = RewardClaimBatchWitness { mode: RewardClaimBatchMode::Leaf, statements: vec![statement], tip: Some(root_proof), children: None };
        let genuine_empty = batch.prove(&empty).unwrap();
        let genuine_leaf = batch.prove(&leaf).unwrap();
        batch.circuit_data.verify(genuine_empty.clone()).unwrap();
        batch.circuit_data.verify(genuine_leaf.clone()).unwrap();
        let claim = BridgeRewardClaimCircuit::new(batch.get_common_circuit_data_ref(), batch.get_verifier_config_ref(), 0);
        let claim_for = |batch_proof, claims| BridgeRewardClaimInput { end_checkpoint_id: 1025, end_checkpoint_root, batch_proof, claims };
        claim.prove(&claim_for(genuine_empty.clone(), Vec::new())).unwrap();
        claim.prove(&claim_for(genuine_leaf.clone(), vec![BridgeRewardClaimWitness { statement_index: 0, anchor_checkpoint_id: 1025, anchor_leaf, anchor_siblings }])).unwrap();
        let carried = |input: &RewardClaimBatchWitness, digest: bool, cap: bool| {
            let mut verifier = batch.get_verifier_config_ref().clone();
            if digest { verifier.circuit_digest.elements[0] += F::ONE; }
            if cap { verifier.constants_sigmas_cap.0[0].elements[0] += F::ONE; }
            let witness = batch.set_witness_with_verifier(input, &verifier).unwrap();
            batch.circuit_data.prove(witness).unwrap()
        };
        for (label, input, source) in [("empty", &empty, &genuine_empty), ("leaf", &leaf, &genuine_leaf)] {
            for (name, digest, cap) in [("digest", true, false), ("cap", false, true)] {
                let proof = carried(input, digest, cap);
                assert_eq!(&proof.public_inputs[..REWARD_CLAIM_BATCH_STATEMENT_LEN], &source.public_inputs[..REWARD_CLAIM_BATCH_STATEMENT_LEN], "{label} {name} changed the business statement");
                assert_ne!(&proof.public_inputs[REWARD_CLAIM_BATCH_STATEMENT_LEN..], &source.public_inputs[REWARD_CLAIM_BATCH_STATEMENT_LEN..], "{label} {name} did not change the carried suffix");
                batch.circuit_data.verify(proof.clone()).unwrap();
                assert!(claim.prove(&claim_for(proof, Vec::new())).is_err(), "reward consumer accepted an unbound {label} {name} suffix");
            }
        }
    }
    #[test]
    fn reward_words_follow_installed_ethereum_index_and_unsigned_user() {
        let (_segment, _merge, root, root_proof, anchor_leaf, anchor_siblings) = reward_tip(11);
        let end_checkpoint_root = HashOut { elements: root_proof.public_inputs[26..30].try_into().unwrap() };
        let batch = RewardClaimBatchCircuit::new(root.get_common_circuit_data_ref(), root.get_verifier_config_ref());
        let statement: [F; REWARD_ROOT_STATEMENT_LEN] = root_proof.public_inputs[..REWARD_ROOT_STATEMENT_LEN].try_into().unwrap();
        let batch_proof = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Leaf, statements: vec![statement], tip: Some(root_proof), children: None }).unwrap();
        for ethereum_index in [0u8, 5] {
            let claim = BridgeRewardClaimCircuit::new(batch.get_common_circuit_data_ref(), batch.get_verifier_config_ref(), ethereum_index);
            let input = BridgeRewardClaimInput { end_checkpoint_id: 1025, end_checkpoint_root, batch_proof: batch_proof.clone(), claims: vec![BridgeRewardClaimWitness { statement_index: 0, anchor_checkpoint_id: 1025, anchor_leaf, anchor_siblings }] };
            let output = claim.prove(&input).unwrap();
            let word = |word: usize, limb: usize| output.public_inputs[6 + word * 8 + limb];
            for limb in 0..7 { assert_eq!(word(1, limb), F::ZERO, "chain limb {limb}"); }
            assert_eq!(word(1, 7), F::from_canonical_u32(u32::from(ethereum_index)));
            for limb in 0..7 { assert_eq!(word(2, limb), F::ZERO, "user limb {limb}"); }
            assert_eq!(word(2, 7), F::from_canonical_u32(11));
            for limb in 0..7 { assert_eq!(word(3, limb), F::ZERO); }
            assert_eq!(word(3, 7), F::from_canonical_u64(BRIDGE_REWARD_CONTRACT_ID));
        }
    }

    #[test]
    fn withdrawal_witness_completes_inactive_slots_and_zero_claims() {
        let policy = BridgeTokenPolicy {
            chain_index: 1, token_contract_id: 7, token_address: [0, 0, 0, 4, 5, 6, 7, 8],
            approved_leaf: PsyContractLeaf { state_tree_height: F::from_canonical_usize(STATE_HEIGHT), ..PsyContractLeaf::default() },
            map_base: 8, capacity: 4,
        };
        let circuit = BridgeWithdrawalClaimCircuit::new(vec![policy]).unwrap();
        let input = BridgeWithdrawalClaimInput { end_checkpoint_id: 0, end_checkpoint_root: HashOut::ZERO, end_gusr: HashOut::ZERO, end_gcon: HashOut::ZERO, claims: Vec::new() };
        let output = circuit.prove(&input).unwrap();
        assert_eq!(output.public_inputs[0], F::ZERO);
        for slot in 0..BRIDGE_CLAIM_CAPACITY {
            for word in 0..BRIDGE_WITHDRAWAL_CLAIM_WORDS {
                for limb in 0..8 {
                    let position = 14 + slot * BRIDGE_WITHDRAWAL_CLAIM_WORDS * 8 + word * 8 + limb;
                    assert_eq!(output.public_inputs[position], F::ZERO, "slot {slot} word {word} limb {limb}");
                }
            }
        }
    }

    #[test]
    fn withdrawal_rejects_unsorted_active_prefix() {
        let policy = BridgeTokenPolicy {
            chain_index: 1, token_contract_id: 7, token_address: [0, 0, 0, 4, 5, 6, 7, 8],
            approved_leaf: PsyContractLeaf { state_tree_height: F::from_canonical_usize(STATE_HEIGHT), ..PsyContractLeaf::default() },
            map_base: 8, capacity: 4,
        };
        let circuit = BridgeWithdrawalClaimCircuit::new(vec![policy.clone()]).unwrap();
        let recipient = [0, 0, 0, 6, 5, 4, 3, 2];
        let amount = [0, 0, 0, 0, 0, 0, 1, 1];
        let leaf_for = |user: u32, nonce_word: [u32; 8]| {
            let nonce_hash = PoseidonHash::hash_no_pad(&nonce_word.map(F::from_canonical_u32));
            let mut key_inputs = vec![F::from_canonical_u64(WITHDRAWAL_NAMESPACE)];
            key_inputs.extend(nonce_hash.elements);
            let key = QHashOut(PoseidonHash::hash_no_pad(&key_inputs));
            let mut value_inputs = vec![F::from_canonical_u32(user)];
            for word in [recipient, policy.token_address, amount, nonce_word] { value_inputs.extend(word.map(F::from_canonical_u32)); }
            value_inputs.push(F::from_canonical_u8(policy.chain_index));
            (key, QHashOut(PoseidonHash::hash_no_pad(&value_inputs)))
        };
        let (key_a, value_a) = leaf_for(5, [1, 2, 3, 4, 5, 6, 7, 8]);
        let (key_b, value_b) = leaf_for(11, [8, 7, 6, 5, 4, 3, 2, 1]);
        let sentinel = IMTContractStateLeaf { key: QHashOut::ZERO, value: QHashOut::from_values(2, 0, 0, 0), next_key: key_a, next_index: F::from_canonical_u32(policy.map_base + 1) };
        let member_a = IMTContractStateLeaf { key: key_a, value: value_a, next_key: key_b, next_index: F::from_canonical_u32(policy.map_base + 2) };
        let member_b = IMTContractStateLeaf { key: key_b, value: value_b, next_key: QHashOut::ZERO, next_index: F::ZERO };
        let mut state = BTreeMap::new();
        state.insert(policy.map_base as u64, sentinel.qfhash::<PoseidonHash>().0);
        state.insert((policy.map_base + 1) as u64, member_a.qfhash::<PoseidonHash>().0);
        state.insert((policy.map_base + 2) as u64, member_b.qfhash::<PoseidonHash>().0);
        let (sentinel_siblings, state_root) = sparse_path::<STATE_HEIGHT>(&state, policy.map_base as u64);
        let (siblings_a, root_a) = sparse_path::<STATE_HEIGHT>(&state, (policy.map_base + 1) as u64);
        let (siblings_b, root_b) = sparse_path::<STATE_HEIGHT>(&state, (policy.map_base + 2) as u64);
        assert_eq!(root_a, state_root);
        assert_eq!(root_b, state_root);
        let contracts = Leaves::from([(u64::from(policy.token_contract_id), state_root)]);
        let (contract_siblings, contract_root) = sparse_path::<{ GLOBAL_CONTRACT_TREE_HEIGHT as usize }>(&contracts, u64::from(policy.token_contract_id));
        let definitions = Leaves::from([(u64::from(policy.token_contract_id), contract_leaf_hash(&policy.approved_leaf))]);
        let (global_contract_siblings, gcon) = sparse_path::<{ GLOBAL_CONTRACT_TREE_HEIGHT as usize }>(&definitions, u64::from(policy.token_contract_id));
        let user_leaf_a = PsyUserLeaf { user_id: F::from_canonical_u32(5), user_state_tree_root: QHashOut(contract_root), ..PsyUserLeaf::default() };
        let user_leaf_b = PsyUserLeaf { user_id: F::from_canonical_u32(11), user_state_tree_root: QHashOut(contract_root), ..PsyUserLeaf::default() };
        let mut users = BTreeMap::new();
        users.insert(5, user_leaf_a.alghash::<PoseidonHash>().0);
        users.insert(11, user_leaf_b.alghash::<PoseidonHash>().0);
        let (gsiblings_a, gusr_a) = sparse_path::<{ GLOBAL_USER_TREE_HEIGHT as usize }>(&users, 5);
        let (gsiblings_b, gusr_b) = sparse_path::<{ GLOBAL_USER_TREE_HEIGHT as usize }>(&users, 11);
        assert_eq!(gusr_a, gusr_b);
        let claim_a = BridgeWithdrawalClaimWitness {
            policy_ordinal: 0,
            user_contract: UserContractState { checkpoint_tree_root: QHashOut::default(), user_leaf: user_leaf_a, start_contract_state_root: QHashOut(state_root), contract_id: F::from_canonical_u32(policy.token_contract_id), checkpoint_id: F::from_canonical_u8(policy.chain_index) },
            user_siblings: gsiblings_a, contract_siblings, global_contract_siblings, member_index: policy.map_base + 1, member: member_a, member_siblings: siblings_a,
            sentinel: sentinel.clone(), sentinel_siblings: sentinel_siblings.clone(), recipient, token_address: policy.token_address, amount, nonce: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let claim_b = BridgeWithdrawalClaimWitness {
            policy_ordinal: 0,
            user_contract: UserContractState { checkpoint_tree_root: QHashOut::default(), user_leaf: user_leaf_b, start_contract_state_root: QHashOut(state_root), contract_id: F::from_canonical_u32(policy.token_contract_id), checkpoint_id: F::from_canonical_u8(policy.chain_index) },
            user_siblings: gsiblings_b, contract_siblings, global_contract_siblings, member_index: policy.map_base + 2, member: member_b, member_siblings: siblings_b,
            sentinel, sentinel_siblings, recipient, token_address: policy.token_address, amount, nonce: [8, 7, 6, 5, 4, 3, 2, 1],
        };
        let input = BridgeWithdrawalClaimInput { end_checkpoint_id: 12, end_checkpoint_root: HashOut::from_partial(&[F::from_canonical_u64(12)]), end_gusr: gusr_a, end_gcon: gcon, claims: vec![claim_a, claim_b] };
        circuit.prove(&input).unwrap();
        let mut bad = input.clone();
        bad.claims.reverse();
        assert!(circuit.prove(&bad).is_err(), "descending active prefix must fail");
    }

    #[test]
    fn installed_policy_rejects_invalid_bounds_and_order() {
        let policy = BridgeTokenPolicy {
            chain_index: 1, token_contract_id: 7, token_address: [0, 0, 0, 4, 5, 6, 7, 8],
            approved_leaf: PsyContractLeaf { state_tree_height: F::from_canonical_usize(STATE_HEIGHT), ..Default::default() },
            map_base: 8, capacity: 4,
        };
        assert!(BridgeWithdrawalClaimCircuit::new(Vec::new()).is_err());
        assert!(BridgeWithdrawalClaimCircuit::new(vec![policy.clone(); 256]).is_err());
        assert!(BridgeWithdrawalClaimCircuit::new(vec![policy.clone(), policy.clone()]).is_err());
        for mutation in 0..5 {
            let mut invalid = policy.clone();
            match mutation {
                0 => invalid.token_contract_id = 1 << 24,
                1 => invalid.token_address[2] = 1,
                2 => invalid.approved_leaf.state_tree_height = F::from_canonical_u32(31),
                3 => invalid.capacity = 0,
                _ => invalid.map_base = u32::MAX,
            }
            assert!(BridgeWithdrawalClaimCircuit::new(vec![invalid]).is_err());
        }
        let mut later = policy.clone();
        later.chain_index += 1;
        assert!(BridgeWithdrawalClaimCircuit::new(vec![later, policy]).is_err());
    }
    #[test]
    fn reward_consumer_rejects_duplicate_index_and_accepts_identical_statements() {
        let (_segment, _merge, root, first_proof, anchor_leaf, anchor_siblings) = reward_tip(7);
        let (_segment, _merge, _root, second_proof, _, _) = reward_tip(11);
        let batch = RewardClaimBatchCircuit::new(root.get_common_circuit_data_ref(), root.get_verifier_config_ref());
        let first: [F; REWARD_ROOT_STATEMENT_LEN] = first_proof.public_inputs[..REWARD_ROOT_STATEMENT_LEN].try_into().unwrap();
        let second: [F; REWARD_ROOT_STATEMENT_LEN] = second_proof.public_inputs[..REWARD_ROOT_STATEMENT_LEN].try_into().unwrap();
        let end_checkpoint_root = HashOut { elements: first_proof.public_inputs[26..30].try_into().unwrap() };
        let first_leaf = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Leaf, statements: vec![first], tip: Some(first_proof.clone()), children: None }).unwrap();
        let repeated_leaf = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Leaf, statements: vec![first], tip: Some(first_proof), children: None }).unwrap();
        let second_leaf = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Leaf, statements: vec![second], tip: Some(second_proof), children: None }).unwrap();
        let duplicate = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Pair, statements: vec![first, first], tip: None, children: Some([first_leaf.clone(), repeated_leaf]) }).unwrap();
        batch.circuit_data.verify(duplicate.clone()).unwrap();
        let claim = BridgeRewardClaimCircuit::new(batch.get_common_circuit_data_ref(), batch.get_verifier_config_ref(), 0);
        let witness = |statement_index| BridgeRewardClaimWitness { statement_index, anchor_checkpoint_id: 1025, anchor_leaf, anchor_siblings };
        let repeated = BridgeRewardClaimInput { end_checkpoint_id: 1025, end_checkpoint_root, batch_proof: duplicate, claims: vec![witness(0), witness(0)] };
        assert!(claim.prove(&repeated).is_err(), "reward consumer accepted a repeated statement index");
        let distinct = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Pair, statements: vec![first, second], tip: None, children: Some([first_leaf, second_leaf]) }).unwrap();
        batch.circuit_data.verify(distinct.clone()).unwrap();
        let accepted = BridgeRewardClaimInput { end_checkpoint_id: 1025, end_checkpoint_root, batch_proof: distinct, claims: vec![witness(1), witness(0)] };
        claim.prove(&accepted).unwrap();
    }
    #[test]
    fn reward_reversed_user_order_has_no_claim_circuit_constraint() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let count = builder.add_virtual_target();
        let claims: [[[U32Target; 8]; BRIDGE_REWARD_CLAIM_WORDS]; BRIDGE_CLAIM_CAPACITY] =
            std::array::from_fn(|_| std::array::from_fn(|_| words(&mut builder)));
        let _ = (count, claims);
        let data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        witness.set_target(count, F::from_canonical_u32(2)).unwrap();
        for (slot, claim) in claims.iter().enumerate() {
            for (word, limbs) in claim.iter().enumerate() {
                for (limb, target) in limbs.iter().enumerate() {
                    let value = if slot < 2 && word == 2 && limb == 7 { if slot == 0 { 11 } else { 7 } } else { 0 };
                    witness.set_u32_target(*target, value).unwrap();
                }
            }
        }
        assert!(data.prove(witness).is_ok(), "reversed reward user order is not a claim-circuit constraint");
    }
}
