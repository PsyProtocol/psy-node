use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::{hash_types::{HashOut, HashOutTarget}, poseidon::PoseidonHash},
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_client_data::qdata::checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf};
use psy_common_circuit::{
    builder::{connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore},
    circuits::zk_signature3::core::PsyBasicZKSignatureCircuit,
    traits::CreatableTarget,
};
use psy_config::network_constants::{CHECKPOINT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT};
use psy_crypto::common::user_id::circuit_user_registration_tree_index_bits_to_user_id;
use psy_network_circuit::gadgets::qdata::{
    checkpoint::PsyCheckpointLeafGadget,
    checkpoint_state_roots::PsyCheckpointGlobalStateRootsGadget,
};
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, core::CircuitBuilderHelpersCore, verify::CircuitBuilderVerifyProofHelpers};
use psy_plonky2_common_circuits::hash::keccak::keccak256_bytes_targets;
use psy_plonky2_common_circuits::hash::merkle::gadgets::merkle_proof::MerkleProofGadget;
use psy_ups_circuit::signature::sd_key_plonky2::get_zk_public_key_param;

use super::{
    historical_merkle_proof::historical_merkle_proof,
    user_reward_checkpoint_aggregate::{
        UserRewardCheckpointAggregateProof, REWARD_CLAIM_MAX_CHECKPOINTS,
        USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT, USER_REWARD_CHECKPOINT_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT,
        USER_REWARD_CHECKPOINT_AGGREGATE_TOTAL_PUBLIC_INPUT_COUNT,
    },
};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

pub const REWARD_CLAIM_MESSAGE_BYTES: usize = 32 * (8 + REWARD_CLAIM_MAX_CHECKPOINTS);
pub const REWARD_CLAIM_PUBLIC_INPUT_BITS: usize = 256;
/// `keccak256(bytes("PsyReward/TokenCheckpointClaim/1"))`, legacy Keccak-256.
/// The expression is the authority; this compiled constant must match it.
const CLAIM_DOMAIN: [u8; 32] = [
    0x29, 0x67, 0x8e, 0x1c, 0x24, 0x93, 0x50, 0xea, 0x65, 0xb5, 0x92, 0xbe, 0xe1, 0x95, 0x5e, 0x40,
    0x4a, 0x14, 0xd5, 0x28, 0x17, 0xbe, 0xd2, 0x09, 0xba, 0x53, 0x62, 0x09, 0x69, 0x6f, 0x23, 0xd6,
];
const GOLDILOCKS_ORDER: u64 = 0xffff_ffff_0000_0001;
const CHECKPOINT_IDS: std::ops::Range<usize> = 15..15 + REWARD_CLAIM_MAX_CHECKPOINTS;

pub struct RewardClaimWrapWitness {
    pub state_manager: [u8; 20],
    pub token: [u8; 20],
    pub anchor_checkpoint_id: u32,
    pub anchor_leaf: PsyCheckpointLeaf<F>,
    pub anchor_siblings: [HashOut<F>; CHECKPOINT_TREE_HEIGHT as usize],
    pub global_roots: PsyCheckpointGlobalStateRoots<F>,
    pub registration_leaf: HashOut<F>,
    pub registration_index: u64,
    pub registration_siblings: [HashOut<F>; GLOBAL_USER_TREE_HEIGHT as usize],
    pub private_key: HashOut<F>,
}

#[derive(Debug)]
pub struct RewardClaimWrapCircuit {
    proof_target: ProofWithPublicInputsTarget<D>,
    verifier_data_target: VerifierCircuitTarget,
    state_manager: [Target; 20],
    token: [Target; 20],
    anchor_checkpoint_id: Target,
    anchor_leaf: PsyCheckpointLeafGadget,
    anchor_siblings: [HashOutTarget; CHECKPOINT_TREE_HEIGHT as usize],
    global_roots: PsyCheckpointGlobalStateRootsGadget,
    registration: MerkleProofGadget,
    private_key: HashOutTarget,
    pub circuit_data: CircuitData<F, C, D>,
}

fn range_u32(builder: &mut CircuitBuilder<F, D>, value: Target) {
    builder.range_check(value, 32);
}

fn assert_not_equal(builder: &mut CircuitBuilder<F, D>, left: Target, right: Target) {
    let equal = builder.is_equal(left, right);
    builder.assert_zero(equal.target);
}

fn assert_canonical_goldilocks(builder: &mut CircuitBuilder<F, D>, bits: &[BoolTarget]) {
    let modulus = GOLDILOCKS_ORDER.to_le_bytes();
    let mut decided = builder._false();
    let mut less = builder._false();
    for index in (0..bits.len()).rev() {
        let bit = bits[index];
        let modulus_bit = builder.constant_bool(((modulus[index / 8] >> (index % 8)) & 1) == 1);
        let value_zero = builder.not(bit);
        let modulus_zero = builder.not(modulus_bit);
        let bit_less = builder.and(value_zero, modulus_bit);
        let bit_greater = builder.and(bit, modulus_zero);
        let undecided = builder.not(decided);
        let newly_less = builder.and(undecided, bit_less);
        let differs = builder.or(bit_less, bit_greater);
        less = builder.or(less, newly_less);
        decided = builder.or(decided, differs);
    }
    builder.assert_one(less.target);
}

fn be_word(builder: &mut CircuitBuilder<F, D>, value: Target, bits: usize) -> Vec<Target> {
    let limbs = builder.split_le(value, bits);
    let mut bytes = Vec::with_capacity(32);
    bytes.extend(std::iter::repeat(builder.zero()).take(32 - bits / 8));
    for offset in (0..bits / 8).rev() {
        let mut byte = builder.zero();
        let mut weight = builder.one();
        let two = builder.two();
        for bit in &limbs[offset * 8..(offset + 1) * 8] {
            byte = builder.mul_add(weight, bit.target, byte);
            weight = builder.mul(weight, two);
        }
        bytes.push(byte);
    }
    bytes
}

fn bytes_from_bits(builder: &mut CircuitBuilder<F, D>, bits: &[BoolTarget]) -> Vec<Target> {
    let mut bytes = Vec::with_capacity(bits.len() / 8);
    for offset in (0..bits.len() / 8).rev() {
        let mut byte = builder.zero();
        let mut weight = builder.one();
        let two = builder.two();
        for bit in &bits[offset * 8..(offset + 1) * 8] {
            byte = builder.mul_add(weight, bit.target, byte);
            weight = builder.mul(weight, two);
        }
        bytes.push(byte);
    }
    bytes
}

/// Packs the static `8+K` ABI-word checkpoint-claim message in place. Shared by
/// the wrap circuit and the assembly test so the two cannot drift.
fn register_reward_claim_message(
    builder: &mut CircuitBuilder<F, D>,
    statement: &[Target],
    root_bits: &[Vec<BoolTarget>],
    state_manager: &[Target; 20],
    token: &[Target; 20],
) -> [Target; REWARD_CLAIM_MESSAGE_BYTES] {
    assert_eq!(statement.len(), USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT);
    assert_eq!(root_bits.len(), 4);
    assert_eq!(CHECKPOINT_IDS.end, USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT);
    let zero = builder.zero();
    let mut bytes = [zero; REWARD_CLAIM_MESSAGE_BYTES];
    let mut at = 0usize;
    let mut place = |bytes: &mut [Target; REWARD_CLAIM_MESSAGE_BYTES], at: &mut usize, word: Vec<Target>| {
        for byte in word {
            bytes[*at] = byte;
            *at += 1;
        }
    };
    for (slot, byte) in bytes.iter_mut().zip(CLAIM_DOMAIN) {
        *slot = builder.constant(F::from_canonical_u8(byte));
    }
    at = 32;
    for address in [token, state_manager] {
        place(&mut bytes, &mut at, std::iter::repeat(zero).take(12).chain(address.iter().copied()).collect());
    }
    place(&mut bytes, &mut at, be_word(builder, statement[0], 32));
    let mut recipient = Vec::with_capacity(32);
    recipient.extend(std::iter::repeat(zero).take(12));
    for index in (1..6).rev() {
        recipient.extend(be_word(builder, statement[index], 32).into_iter().skip(28));
    }
    place(&mut bytes, &mut at, recipient);
    let mut checkpoint_root = Vec::with_capacity(32);
    for bits in root_bits.iter().rev() {
        checkpoint_root.extend(bytes_from_bits(builder, bits));
    }
    place(&mut bytes, &mut at, checkpoint_root);
    place(&mut bytes, &mut at, be_word(builder, statement[10], 32));
    let mut total_limbs = Vec::with_capacity(16);
    for index in (11..15).rev() {
        total_limbs.extend(be_word(builder, statement[index], 32).into_iter().skip(28));
    }
    let mut total = Vec::with_capacity(32);
    total.extend(std::iter::repeat(zero).take(16));
    total.extend(total_limbs);
    place(&mut bytes, &mut at, total);
    for index in CHECKPOINT_IDS {
        place(&mut bytes, &mut at, be_word(builder, statement[index], 32));
    }
    assert_eq!(at, REWARD_CLAIM_MESSAGE_BYTES);
    bytes
}

fn chunk_bits(builder: &mut CircuitBuilder<F, D>, bytes: &[Target]) -> Vec<Target> {
    let mut bits = Vec::with_capacity(64);
    for byte in bytes.iter().rev() {
        bits.extend(builder.split_le(*byte, 8).into_iter().map(|bit| bit.target));
    }
    bits
}

fn register_reward_claim_commitment(builder: &mut CircuitBuilder<F, D>, message: &[Target]) -> usize {
    let commitment = keccak256_bytes_targets(builder, message);
    let mut bytes = Vec::with_capacity(32);
    for word in commitment {
        let bits = builder.split_le(word.0, 32);
        for byte in bits.chunks_exact(8) {
            bytes.push(builder.le_sum(byte.iter()));
        }
    }
    let mut commitment_bit_count = 0;
    for chunk in bytes.chunks_exact(8) {
        let bits = chunk_bits(builder, chunk);
        commitment_bit_count += bits.len();
        builder.register_public_inputs(&bits);
    }
    commitment_bit_count
}

impl RewardClaimWrapCircuit {
    pub fn new(
        common_data: &CommonCircuitData<F, D>,
        fingerprint: QHashOut<F>,
        inner_verifier_data_cap_height: usize,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let proof_target = builder.add_virtual_proof_with_pis(common_data);
        let verifier_data_target = builder.add_virtual_verifier_data(inner_verifier_data_cap_height);
        builder.verify_proof::<C>(&proof_target, &verifier_data_target, common_data);
        let expected = builder.constant_hash(fingerprint.into());
        let actual = builder.get_circuit_fingerprint::<<C as GenericConfig<D>>::Hasher>(&verifier_data_target);
        builder.connect_hashes(expected, actual);

        let statement = &proof_target.public_inputs;
        assert_eq!(statement.len(), USER_REWARD_CHECKPOINT_AGGREGATE_TOTAL_PUBLIC_INPUT_COUNT);
        assert_eq!(
            USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT + USER_REWARD_CHECKPOINT_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT,
            USER_REWARD_CHECKPOINT_AGGREGATE_TOTAL_PUBLIC_INPUT_COUNT
        );
        assert_eq!(USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT, 15 + REWARD_CLAIM_MAX_CHECKPOINTS);
        assert_eq!(USER_REWARD_CHECKPOINT_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT, 68);
        assert_eq!(REWARD_CLAIM_PUBLIC_INPUT_BITS, 256);
        assert_eq!(verifier_data_target.constants_sigmas_cap.0.len(), 16);
        let suffix = USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT;
        for index in 0..4 {
            builder.connect(statement[suffix + index], verifier_data_target.circuit_digest.elements[index]);
        }
        for (cap_index, cap) in verifier_data_target.constants_sigmas_cap.0.iter().enumerate() {
            for limb in 0..4 {
                builder.connect(statement[suffix + 4 + 4 * cap_index + limb], cap.elements[limb]);
            }
        }
        range_u32(&mut builder, statement[0]);
        let zero = builder.zero();
        for index in 1..6 {
            range_u32(&mut builder, statement[index]);
        }
        let mut recipient = builder.zero();
        for index in 1..6 {
            recipient = builder.add(recipient, statement[index]);
        }
        assert_not_equal(&mut builder, recipient, zero);
        let mut root_bits = Vec::with_capacity(4);
        for index in 6..10 {
            root_bits.push(builder.split_le(statement[index], 64));
        }
        for bits in &root_bits {
            assert_canonical_goldilocks(&mut builder, bits);
        }
        range_u32(&mut builder, statement[10]);
        assert_not_equal(&mut builder, statement[10], zero);
        for index in 11..15 {
            range_u32(&mut builder, statement[index]);
        }
        let mut amount = builder.zero();
        for index in 11..15 {
            amount = builder.add(amount, statement[index]);
        }
        assert_not_equal(&mut builder, amount, zero);
        for index in CHECKPOINT_IDS {
            range_u32(&mut builder, statement[index]);
        }

        let checkpoint_tree_root = HashOutTarget { elements: std::array::from_fn(|index| statement[6 + index]) };
        let anchor_checkpoint_id = builder.add_virtual_target();
        let anchor_leaf = PsyCheckpointLeafGadget::create_virtual(&mut builder);
        let anchor = historical_merkle_proof(
            &mut builder, [anchor_checkpoint_id, zero], &anchor_leaf, [anchor_checkpoint_id, zero], checkpoint_tree_root,
        );
        let global_roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(&mut builder);
        let global_hash = global_roots.to_hash::<PoseidonHash, F, D>(&mut builder);
        builder.connect_hashes(global_hash, anchor_leaf.global_chain_root);
        let (registration, registration_index_bits) = MerkleProofGadget::add_virtual_to_get_index_bits::<PoseidonHash, F, D>(
            &mut builder, GLOBAL_USER_TREE_HEIGHT as usize,
        );
        builder.connect_hashes(registration.root, global_roots.user_registration_tree_root);
        let signature_fingerprint = builder.constant_hash(PsyBasicZKSignatureCircuit::<C, D>::new().fingerprint.0);
        let private_key = builder.add_virtual_hash();
        let public_key_param = get_zk_public_key_param::<C, D>(&mut builder, &private_key);
        let registration_leaf = builder.hash_two_to_one::<PoseidonHash>(signature_fingerprint, public_key_param);
        builder.connect_hashes(registration.value, registration_leaf);
        builder.assert_non_zero_hash(registration.value);
        let mapped_user_id = circuit_user_registration_tree_index_bits_to_user_id::<PoseidonHash, F, D>(
            &mut builder, registration.index, &registration_index_bits, GLOBAL_USER_TREE_HEIGHT as usize,
        );
        builder.connect(mapped_user_id, statement[0]);
        for index in CHECKPOINT_IDS {
            builder.ensure_is_less_than_or_equal(32, statement[index], anchor_checkpoint_id);
        }

        let state_manager: [Target; 20] = std::array::from_fn(|_| builder.add_virtual_target());
        let token: [Target; 20] = std::array::from_fn(|_| builder.add_virtual_target());
        for byte in state_manager.iter().chain(&token) {
            let _bits = builder.split_le(*byte, 8);
        }
        let message = register_reward_claim_message(
            &mut builder, &statement[..USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT], &root_bits, &state_manager, &token,
        );
        let commitment_bit_count = register_reward_claim_commitment(&mut builder, &message);
        assert_eq!(commitment_bit_count, REWARD_CLAIM_PUBLIC_INPUT_BITS);
        let circuit_data = builder.build::<C>();
        assert_eq!(circuit_data.common.num_public_inputs, REWARD_CLAIM_PUBLIC_INPUT_BITS);
        Self {
            proof_target, verifier_data_target, state_manager, token, anchor_checkpoint_id, anchor_leaf,
            anchor_siblings: anchor.path.siblings.try_into().expect("historical checkpoint path is exactly CHECKPOINT_TREE_HEIGHT"), global_roots, registration, private_key, circuit_data,
        }
    }

    pub fn prove(
        &self,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        aggregate: &UserRewardCheckpointAggregateProof,
        witness: &RewardClaimWrapWitness,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        anyhow::ensure!(
            witness.registration_index < 1u64 << (GLOBAL_USER_TREE_HEIGHT as u64),
            "registration index exceeds tree height",
        );
        let mut partial = PartialWitness::new();
        partial.set_proof_with_pis_target(&self.proof_target, aggregate)?;
        partial.set_verifier_data_target(&self.verifier_data_target, verifier_data)?;
        for (target, byte) in self.state_manager.iter().zip(witness.state_manager) {
            partial.set_target(*target, F::from_canonical_u8(byte))?;
        }
        for (target, byte) in self.token.iter().zip(witness.token) {
            partial.set_target(*target, F::from_canonical_u8(byte))?;
        }
        partial.set_target(self.anchor_checkpoint_id, F::from_canonical_u32(witness.anchor_checkpoint_id))?;
        self.anchor_leaf.set_witness(&mut partial, &witness.anchor_leaf)?;
        for (target, sibling) in self.anchor_siblings.iter().zip(witness.anchor_siblings) {
            partial.set_hash_target(*target, sibling)?;
        }
        self.global_roots.set_witness(&mut partial, &witness.global_roots)?;
        self.registration.set_witness_generic(
            &mut partial, F::from_canonical_u64(witness.registration_index), QHashOut(witness.registration_leaf),
            &witness.registration_siblings.map(QHashOut),
        )?;
        partial.set_hash_target(self.private_key, witness.private_key)?;
        self.circuit_data.prove(partial)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{iop::witness::PartialWitness, plonk::circuit_builder::CircuitBuilder};

    #[test]
    fn reward_claim_commitment_matches_full_message_keccak() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let statement: Vec<_> = (0..USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT).map(|_| builder.add_virtual_target()).collect();
        let root_bits: Vec<_> = (6..10).map(|index| builder.split_le(statement[index], 64)).collect();
        let state_manager: [Target; 20] = std::array::from_fn(|_| builder.add_virtual_target());
        let token: [Target; 20] = std::array::from_fn(|_| builder.add_virtual_target());
        let message = register_reward_claim_message(&mut builder, &statement, &root_bits, &state_manager, &token);
        register_reward_claim_commitment(&mut builder, &message);
        let circuit_data = builder.build::<C>();
        for count in [1usize, 3, REWARD_CLAIM_MAX_CHECKPOINTS] {
        let mut values = vec![0u64; USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT];
        values[0] = 7;
        values[1] = 0x0102_0304;
        values[2] = 0x0506_0708;
        values[3] = 0x090a_0b0c;
        values[4] = 0x0d0e_0f10;
        values[5] = 0x1112_1314;
        values[6] = 0x1111_1111_0000_0019;
        values[7] = 0x2222_2222_0000_001a;
        values[8] = 0x3333_3333_0000_001b;
        values[9] = 0x4444_4444_0000_001c;
        values[10] = count as u64;
        values[11] = 0x4444_4444;
        values[12] = 0x5555_5555;
        values[13] = 0x6666_6666;
        values[14] = 0x7777_7777;
        for index in 0..REWARD_CLAIM_MAX_CHECKPOINTS {
            values[15 + index] = if index < count { index as u64 } else { 0 };
        }
        let state_manager_value = [0x43u8; 20];
        let token_value = [0x45u8; 20];
        let mut witness = PartialWitness::new();
        for (target, value) in statement.iter().zip(values.iter().copied()) {
            witness.set_target(*target, F::from_canonical_u64(value)).unwrap();
        }
        for (targets, value) in [(&state_manager, state_manager_value), (&token, token_value)] {
            for (target, byte) in targets.iter().zip(value) {
                witness.set_target(*target, F::from_canonical_u8(byte)).unwrap();
            }
        }
        let proved = circuit_data.prove(witness).unwrap();

        let word = |value: u64| {
            let mut bytes = [0u8; 32];
            bytes[24..].copy_from_slice(&value.to_be_bytes());
            bytes
        };
        let address = |value: [u8; 20]| {
            let mut bytes = [0u8; 32];
            bytes[12..].copy_from_slice(&value);
            bytes
        };
        let mut hasher = tiny_keccak::Keccak::v256();
        let mut domain = [0u8; 32];
        tiny_keccak::Hasher::update(&mut hasher, b"PsyReward/TokenCheckpointClaim/1");
        tiny_keccak::Hasher::finalize(hasher, &mut domain);
        let mut expected = Vec::new();
        expected.extend(domain);
        expected.extend(address(token_value));
        expected.extend(address(state_manager_value));
        expected.extend(word(values[0]));
        expected.extend([0u8; 12]);
        for index in (1..6).rev() {
            expected.extend((values[index] as u32).to_be_bytes());
        }
        for index in (6..10).rev() {
            expected.extend(values[index].to_be_bytes());
        }
        expected.extend(word(values[10]));
        let mut total = 0u128;
        for index in 0..4 {
            total += (values[11 + index] as u128) << (32 * index);
        }
        expected.extend([0u8; 16]);
        expected.extend(total.to_be_bytes());
        for index in 0..REWARD_CLAIM_MAX_CHECKPOINTS {
            expected.extend(word(values[15 + index]));
        }
        assert_eq!(expected.len(), REWARD_CLAIM_MESSAGE_BYTES);
        assert_eq!(REWARD_CLAIM_PUBLIC_INPUT_BITS, 256);
        let mut hasher = tiny_keccak::Keccak::v256();
        let mut digest = [0u8; 32];
        tiny_keccak::Hasher::update(&mut hasher, &expected);
        tiny_keccak::Hasher::finalize(hasher, &mut digest);
        let recovered = proved.public_inputs.chunks(64).flat_map(|group| {
            (0..8).map(move |byte| {
                group[(7 - byte) * 8..(8 - byte) * 8].iter().enumerate()
                    .fold(0u8, |accumulator, (index, bit)| accumulator + ((bit.to_canonical_u64() as u8) << index))
            })
        }).collect::<Vec<_>>();
        assert_eq!(recovered.len(), 32);
        assert_eq!(recovered, digest);
        circuit_data.verify(proved.clone()).unwrap();
        let mut tampered = proved;
        tampered.public_inputs[0] = F::ONE - tampered.public_inputs[0];
        assert!(circuit_data.verify(tampered).is_err());
        }
    }

    fn prove_canonical_goldilocks(value: u64) -> bool {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let bits: Vec<BoolTarget> = (0..64).map(|_| builder.add_virtual_bool_target_unsafe()).collect();
        assert_canonical_goldilocks(&mut builder, &bits);
        let bit_targets: Vec<_> = bits.iter().map(|bit| bit.target).collect();
        builder.register_public_inputs(&bit_targets);
        let circuit_data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        for (index, bit) in bits.iter().enumerate() {
            witness.set_target(bit.target, F::from_bool(((value >> index) & 1) == 1)).unwrap();
        }
        circuit_data.prove(witness).is_ok()
    }

    #[test]
    fn reward_claim_goldilocks_bits_reject_modulus_and_above() {
        assert!(prove_canonical_goldilocks(GOLDILOCKS_ORDER - 1));
        assert!(!prove_canonical_goldilocks(GOLDILOCKS_ORDER));
        assert!(!prove_canonical_goldilocks(u64::MAX));
    }

    #[test]
    fn wrapper_rejects_wrong_anchor_index_key_user_recipient_and_list() {
        use plonky2::hash::hash_types::HashOut;
        use plonky2::plonk::config::Hasher;
        use psy_crypto::hash::traits::qhashable::QFieldHashable;
        use crate::bridge::circuits::user_reward_checkpoint_aggregate::{
            UserRewardCheckpointAggregateCircuit, UserRewardCheckpointAggregateWitness,
        };
        use crate::bridge::circuits::user_reward_tree::{
            UserRewardAggregateCircuit, UserRewardAggregateWitness, UserRewardLeafCircuit, UserRewardRootCircuit,
        };
        use crate::bridge::circuits::user_reward_tree::tests::{path, registration_membership, reward_root, Fixture};
        use crate::qstandard::QStandardCircuit;

        let leaf = UserRewardLeafCircuit::new();
        let jobs = UserRewardAggregateCircuit::new(&leaf);
        let root = UserRewardRootCircuit::new(&jobs);
        let aggregate = UserRewardCheckpointAggregateCircuit::new(&root);
        let wrapper = RewardClaimWrapCircuit::new(aggregate.get_common_circuit_data_ref(), aggregate.fingerprint, 4);
        let mut fixture = Fixture::for_user(7, 12);
        let lifted = jobs.prove(&UserRewardAggregateWitness::Leaf { leaf: leaf.prove(&fixture.node(10, 0)).unwrap() }).unwrap();
        let proved = reward_root(&root, &fixture, 1, lifted);
        let checkpoint = aggregate.prove(&UserRewardCheckpointAggregateWitness::Root { root: proved }).unwrap();
        let (registration_leaf, registration_index, registration_siblings, global_roots) = registration_membership(7);
        let honest = RewardClaimWrapWitness {
            state_manager: [0x11; 20], token: [0x22; 20], anchor_checkpoint_id: fixture.anchor_checkpoint_id,
            anchor_leaf: fixture.anchor_leaf.clone(),
            anchor_siblings: path::<32>(&fixture.checkpoints, u64::from(fixture.anchor_checkpoint_id), HashOut::ZERO).0,
            global_roots, registration_leaf, registration_index, registration_siblings,
            private_key: QHashOut::from_values(17, 23, 31, 47).0,
        };
        let accepted = wrapper.prove(aggregate.get_verifier_config_ref(), &checkpoint, &honest).unwrap();
        wrapper.circuit_data.verify(accepted.clone()).unwrap();
        assert_eq!(accepted.public_inputs.len(), REWARD_CLAIM_PUBLIC_INPUT_BITS);

        let (other_leaf, other_index, other_siblings, _) = registration_membership(8);
        let mut wrong_anchor = honest.anchor_leaf.clone();
        wrong_anchor.global_chain_root.0.elements[0] += F::ONE;
        let mut wrong_user = honest.global_roots.clone();
        wrong_user.user_registration_tree_root.0.elements[0] += F::ONE;
        let mut redirected = checkpoint.clone();
        redirected.public_inputs[1] += F::ONE;
        let mut substituted = checkpoint.clone();
        substituted.public_inputs[15] = F::from_canonical_u32(11);
        let forge = |anchor_checkpoint_id, anchor_leaf: &PsyCheckpointLeaf<F>, anchor_siblings, global_roots: &PsyCheckpointGlobalStateRoots<F>, registration_leaf, registration_index, registration_siblings: &[HashOut<F>; GLOBAL_USER_TREE_HEIGHT as usize], private_key| RewardClaimWrapWitness {
            state_manager: honest.state_manager, token: honest.token, anchor_checkpoint_id, anchor_leaf: anchor_leaf.clone(), anchor_siblings,
            global_roots: global_roots.clone(), registration_leaf, registration_index, registration_siblings: *registration_siblings, private_key,
        };
        let cases = [
            forge(11, &honest.anchor_leaf, honest.anchor_siblings, &honest.global_roots, honest.registration_leaf, honest.registration_index, &honest.registration_siblings, honest.private_key),
            forge(honest.anchor_checkpoint_id, &honest.anchor_leaf, [HashOut::ZERO; 32], &honest.global_roots, honest.registration_leaf, honest.registration_index, &honest.registration_siblings, honest.private_key),
            forge(honest.anchor_checkpoint_id, &wrong_anchor, honest.anchor_siblings, &honest.global_roots, honest.registration_leaf, honest.registration_index, &honest.registration_siblings, honest.private_key),
            forge(honest.anchor_checkpoint_id, &honest.anchor_leaf, honest.anchor_siblings, &honest.global_roots, honest.registration_leaf, honest.registration_index ^ 1, &honest.registration_siblings, honest.private_key),
            forge(honest.anchor_checkpoint_id, &honest.anchor_leaf, honest.anchor_siblings, &honest.global_roots, other_leaf, other_index, &other_siblings, honest.private_key),
            forge(honest.anchor_checkpoint_id, &honest.anchor_leaf, honest.anchor_siblings, &honest.global_roots, honest.registration_leaf, honest.registration_index, &honest.registration_siblings, QHashOut::from_values(19, 23, 31, 47).0),
            forge(honest.anchor_checkpoint_id, &honest.anchor_leaf, honest.anchor_siblings, &honest.global_roots, HashOut::ZERO, honest.registration_index, &honest.registration_siblings, honest.private_key),
            forge(honest.anchor_checkpoint_id, &honest.anchor_leaf, honest.anchor_siblings, &wrong_user, honest.registration_leaf, honest.registration_index, &honest.registration_siblings, honest.private_key),
        ];
        for forged in cases {
            assert!(wrapper.prove(aggregate.get_verifier_config_ref(), &checkpoint, &forged).is_err());
        }
        assert!(wrapper.prove(aggregate.get_verifier_config_ref(), &redirected, &honest).is_err());
        assert!(wrapper.prove(aggregate.get_verifier_config_ref(), &substituted, &honest).is_err());
        let mut zero_fixture = Fixture::for_user(7, 0);
        let zero_leaf = leaf.prove(&zero_fixture.node(0, 0)).unwrap();
        let zero_root = reward_root(&root, &zero_fixture, 1, jobs.prove(&UserRewardAggregateWitness::Leaf { leaf: zero_leaf }).unwrap());
        let zero = aggregate.prove(&UserRewardCheckpointAggregateWitness::Root { root: zero_root }).unwrap();
        let (zero_registration, zero_index, zero_siblings, zero_roots) = registration_membership(7);
        let zero_anchor = forge(0, &zero_fixture.anchor_leaf, path::<32>(&zero_fixture.checkpoints, 0, HashOut::ZERO).0, &zero_roots, zero_registration, zero_index, &zero_siblings, honest.private_key);
        assert!(wrapper.prove(aggregate.get_verifier_config_ref(), &zero, &zero_anchor).is_err());
    }
}
