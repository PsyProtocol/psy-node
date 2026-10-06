use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use tiny_keccak::{Hasher, Keccak};

use psy_plonky2_basic_helpers::{
    builder::comparison::CircuitBuilderComparison,
    u32::gadgets::arithmetic_u32::U32Target,
};
use crate::hash::keccak::{keccak256_u32_words_be_abi, keccak_f1600, xor_u32_bounded};

/// Eight big-endian u32 words, in byte order. Never Poseidon limb order.
pub type Bytes32Target = [Target; 8];
pub type AddressTarget = [Target; 5];
pub type Hash4Target = [Target; 4];
/// Integer limbs in recursive PI order: low u32, high u32.
pub type U64Target = [Target; 2];

#[derive(Clone, Copy)]
pub enum Domain {
    Config, CircuitSet, DepositAggregate, WithdrawalAggregate, RewardAggregate, Aggregate, LeafCommit, Leaf, Node, Empty, Window, Reward,
    WithdrawalNonce,
}

impl Domain {
    fn label(self) -> &'static str {
        match self {
            Self::Config => "Config", Self::CircuitSet => "CircuitSet",
            Self::DepositAggregate => "A", Self::WithdrawalAggregate => "WithdrawalBatch", Self::RewardAggregate => "RewardBatch", Self::Aggregate => "Batch",
            Self::LeafCommit => "Record", Self::Leaf => "Leaf", Self::Node => "Node",
            Self::Empty => "Empty", Self::Window => "Window", Self::Reward => "Reward",
            Self::WithdrawalNonce => "WithdrawalNonce",
        }
    }
}

pub fn constant_bytes32<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, bytes: [u8; 32],
) -> Bytes32Target {
    std::array::from_fn(|i| builder.constant(F::from_canonical_u32(
        u32::from_be_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()),
    )))
}

pub fn word<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, value: Target, bits: usize,
) -> Bytes32Target {
    assert!((1..=32).contains(&bits));
    builder.range_check(value, bits);
    let mut result = [builder.zero(); 8];
    result[7] = value;
    result
}

pub fn word_u64<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, value: U64Target,
) -> Bytes32Target {
    builder.range_check(value[0], 32);
    builder.range_check(value[1], 32);
    let mut result = [builder.zero(); 8];
    result[6] = value[1];
    result[7] = value[0];
    result
}

pub fn encode_hash4<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, hash: Hash4Target,
) -> Vec<Target> {
    assert_eq!(F::ORDER, 0xffff_ffff_0000_0001);
    let mut words = Vec::with_capacity(32);
    for limb in hash {
        let (low, high) = builder.split_low_high(limb, 32, 64);
        let maximum = builder.constant(F::from_canonical_u32(u32::MAX));
        let high_is_maximum = builder.is_equal(high, maximum);
        let excess = builder.mul(high_is_maximum.target, low);
        builder.assert_zero(excess);
        words.extend(word_u64(builder, [low, high]));
    }
    words
}

pub fn word_address<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, address: AddressTarget,
) -> Bytes32Target {
    let mut result = [builder.zero(); 8];
    for (out, value) in result[3..].iter_mut().zip(address) {
        builder.range_check(value, 32);
        *out = value;
    }
    result
}

pub fn commitment<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, domain: Domain, body: &[Target],
) -> Bytes32Target {
    let mut keccak = Keccak::v256();
    keccak.update(b"PsyBridge/TwoArtifact/1/");
    keccak.update(domain.label().as_bytes());
    let mut digest = [0; 32];
    keccak.finalize(&mut digest);
    let mut preimage = Vec::with_capacity(8 + body.len());
    preimage.extend(constant_bytes32(builder, digest));
    preimage.extend_from_slice(body);
    keccak256_u32_words_be_abi(builder, &preimage).map(|word| word.0)
}

#[derive(Clone, Copy)]
pub struct DepositLeafTarget {
    pub chain_index: Target,
    pub absolute_index: Target,
    pub shield_address: Bytes32Target,
    pub token: AddressTarget,
    pub l2_token_contract_id: Bytes32Target,
    pub amount: Bytes32Target,
    pub note_commitment: Bytes32Target,
}

#[derive(Clone, Copy)]
pub struct WithdrawalLeafTarget {
    pub chain_index: Target,
    pub sender_user_id: Target,
    pub recipient: AddressTarget,
    pub token: AddressTarget,
    pub amount: Bytes32Target,
    pub nonce: Bytes32Target,
}

#[derive(Clone, Copy)]
pub struct RewardLeafTarget {
    pub claim_checkpoint_id: U64Target,
    pub user_id: Target,
    pub height: Target,
    pub path_index: Target,
    pub nullifier_index: Target,
    pub recipient: AddressTarget,
}

#[derive(Clone, Copy)]
pub enum AggregateLeafTarget {
    Deposit(DepositLeafTarget),
    Withdrawal(WithdrawalLeafTarget),
    Reward(RewardLeafTarget),
}

impl AggregateLeafTarget {
    pub fn family(&self) -> u32 {
        match self { Self::Deposit(_) => 1, Self::Withdrawal(_) => 2, Self::Reward(_) => 3 }
    }

    pub fn encode<F: RichField + Extendable<D>, const D: usize>(
        &self, builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let mut body = Vec::new();
        match self {
            Self::Deposit(record) => {
                body.extend(word(builder, record.chain_index, 8));
                body.extend(word(builder, record.absolute_index, 32));
                body.extend(record.shield_address);
                body.extend(word_address(builder, record.token));
                body.extend(record.l2_token_contract_id);
                body.extend(record.amount);
                body.extend(record.note_commitment);
            }
            Self::Withdrawal(record) => {
                body.extend(word(builder, record.chain_index, 8));
                body.extend(word(builder, record.sender_user_id, 32));
                body.extend(word_address(builder, record.recipient));
                body.extend(word_address(builder, record.token));
                body.extend(record.amount);
                body.extend(record.nonce);
            }
            Self::Reward(record) => {
                body.extend(word_u64(builder, record.claim_checkpoint_id));
                body.extend(word(builder, record.user_id, 32));
                body.extend(word(builder, record.height, 8));
                body.extend(word(builder, record.path_index, 32));
                body.extend(word(builder, record.nullifier_index, 32));
                body.extend(word_address(builder, record.recipient));
            }
        }
        for &target in &body { builder.range_check(target, 32); }
        body
    }

    pub fn leaf_commit<F: RichField + Extendable<D>, const D: usize>(
        &self, builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32Target {
        let family = builder.constant(F::from_canonical_u32(self.family()));
        let mut body = word(builder, family, 8).to_vec();
        body.extend(self.encode(builder));
        commitment(builder, Domain::LeafCommit, &body)
    }
}

/// One sponge pass over the capacity, with the final padding block derived from count.
pub fn prefix_commitment<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, domain: Domain, header: &[Target],
    elements: &[Vec<Target>], count: Target, minimum: usize,
) -> Bytes32Target {
    assert!(minimum <= elements.len());
    let width = elements.first().map_or(0, Vec::len);
    assert!(elements.iter().all(|element| element.len() == width));
    builder.range_check(count, 32);
    let minimum = builder.constant(F::from_canonical_usize(minimum));
    let maximum = builder.constant(F::from_canonical_usize(elements.len()));
    builder.ensure_is_less_than_or_equal(32, minimum, count);
    builder.ensure_is_less_than_or_equal(32, count, maximum);
    let mut keccak = Keccak::v256();
    keccak.update(b"PsyBridge/TwoArtifact/1/");
    keccak.update(domain.label().as_bytes());
    let mut digest = [0; 32];
    keccak.finalize(&mut digest);
    let mut words = constant_bytes32(builder, digest).to_vec();
    words.extend_from_slice(header);
    for element in elements { words.extend_from_slice(element); }
    let header_length = builder.constant(F::from_canonical_usize((8 + header.len()) * 4));
    let length = builder.mul_const_add(F::from_canonical_usize(width * 4), count, header_length);
    keccak_prefix_words(builder, &words, length)
}

pub fn keccak_prefix_words<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, words: &[Target], byte_length: Target,
) -> Bytes32Target {
    assert!(words.len() <= u32::MAX as usize / 4);
    builder.range_check(byte_length, 32);
    let capacity = builder.constant(F::from_canonical_usize(words.len() * 4));
    builder.ensure_is_less_than_or_equal(32, byte_length, capacity);
    let zero = builder.zero();
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for &word in words {
        let bits = builder.split_le(word, 32);
        for byte in (0..4).rev() {
            bytes.push(builder.le_sum(bits[byte * 8..byte * 8 + 8].iter()));
        }
    }
    let mut state = [[U32Target(zero); 2]; 25];
    for block in 0..=bytes.len() / 136 {
        let start = builder.constant(F::from_canonical_usize(block * 136));
        let end = builder.constant(F::from_canonical_usize((block + 1) * 136));
        let before_start = builder.is_less_than(32, byte_length, start);
        let active = builder.not(before_start);
        let before_end = builder.is_less_than(32, byte_length, end);
        let final_block = builder.and(active, before_end);
        let mut rate = Vec::with_capacity(136);
        for offset in 0..136 {
            let index = block * 136 + offset;
            let index_target = builder.constant(F::from_canonical_usize(index));
            let padding_start = builder.is_equal(byte_length, index_target);
            let mut byte = bytes.get(index).copied().unwrap_or(zero);
            if index < bytes.len() {
                let real = builder.is_less_than(32, index_target, byte_length);
                let inactive = builder.not(real);
                let padding = builder.mul(inactive.target, byte);
                builder.assert_zero(padding);
            }
            byte = builder.add(byte, padding_start.target);
            if offset == 135 {
                byte = builder.mul_const_add(F::from_canonical_u8(128), final_block.target, byte);
            }
            rate.push(byte);
        }
        let mut next = state;
        for lane in 0..17 {
            let limbs: [U32Target; 2] = std::array::from_fn(|half| {
                let mut limb = zero;
                for byte in (0..4).rev() {
                    limb = builder.mul_const_add(
                        F::from_canonical_u32(256), limb, rate[lane * 8 + half * 4 + byte],
                    );
                }
                U32Target(limb)
            });
            for half in 0..2 {
                next[lane][half] = xor_u32_bounded(builder, state[lane][half], limbs[half]);
            }
        }
        keccak_f1600(builder, &mut next);
        for lane in 0..25 {
            for half in 0..2 {
                state[lane][half] = U32Target(builder.select(active, next[lane][half].0, state[lane][half].0));
            }
        }
    }
    std::array::from_fn(|i| {
        let bits = builder.split_le(state[i / 2][i % 2].0, 32);
        let mut word = zero;
        for byte in 0..4 {
            let value = builder.le_sum(bits[byte * 8..byte * 8 + 8].iter());
            word = builder.mul_const_add(F::from_canonical_u32(256), word, value);
        }
        word
    })
}

pub fn aggregate_commit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, config_hash: Bytes32Target,
    end_id: U64Target, end_root: Hash4Target, first_chunk: Target,
    leaves: &[AggregateLeafTarget], leaf_count: Target,
) -> Bytes32Target {
    assert!(!leaves.is_empty() && leaves.len() <= 32);
    let family = leaves[0].family();
    assert!(leaves.iter().all(|leaf| leaf.family() == family));
    let family = builder.constant(F::from_canonical_u32(family));
    let mut body = config_hash.to_vec();
    body.extend(word_u64(builder, end_id));
    body.extend(encode_hash4(builder, end_root));
    body.extend(word(builder, family, 8));
    body.extend(word(builder, first_chunk, 32));
    let first_leaf = builder.mul_const(F::from_canonical_u32(32), first_chunk);
    body.extend(word(builder, first_leaf, 32));
    body.extend(word(builder, leaf_count, 32));
    let leaves: Vec<_> = leaves.iter().map(|leaf| leaf.encode(builder)).collect();
    prefix_commitment(builder, Domain::Aggregate, &body, &leaves, leaf_count, 1)
}

fn deposit_leaf_header<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, count: Target, ordinal: Target,
) -> Vec<Target> {
    builder.range_check(count, 11);
    let maximum = builder.constant(F::from_canonical_u32(1024));
    builder.ensure_is_less_than_or_equal(11, count, maximum);
    let marker = builder.constant(F::from_canonical_u8(12));
    let mut body = word(builder, marker, 8).to_vec();
    body.extend(word(builder, count, 11));
    body.extend(word(builder, ordinal, 10));
    body
}

pub fn deposit_leaf_node_leaf<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, count: Target, ordinal: Target,
    leaf_commit: Bytes32Target,
) -> Bytes32Target {
    let mut body = deposit_leaf_header(builder, count, ordinal);
    body.extend(leaf_commit);
    commitment(builder, Domain::Leaf, &body)
}

pub fn deposit_leaf_empty<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, count: Target, ordinal: Target,
) -> Bytes32Target {
    let body = deposit_leaf_header(builder, count, ordinal);
    commitment(builder, Domain::Empty, &body)
}

pub fn deposit_leaf_node<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, level: u8,
    left: Bytes32Target, right: Bytes32Target,
) -> Bytes32Target {
    assert!((1..=10).contains(&level));
    let marker = builder.constant(F::from_canonical_u8(12));
    let level = builder.constant(F::from_canonical_u8(level));
    let mut body = word(builder, marker, 8).to_vec();
    body.extend(word(builder, level, 8));
    body.extend(left);
    body.extend(right);
    commitment(builder, Domain::Node, &body)
}

pub fn deposit_leaf_root<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, leaf_commits: &[Bytes32Target; 1024], count: Target,
) -> Bytes32Target {
    let mut nodes = Vec::with_capacity(1024);
    for (j, leaf_commit) in leaf_commits.iter().enumerate() {
        let ordinal = builder.constant(F::from_canonical_usize(j));
        let real = builder.is_less_than(11, ordinal, count);
        let inactive = builder.not(real);
        for &word in leaf_commit {
            builder.range_check(word, 32);
            let padding = builder.mul(inactive.target, word);
            builder.assert_zero(padding);
        }
        let leaf = deposit_leaf_node_leaf(builder, count, ordinal, *leaf_commit);
        let empty = deposit_leaf_empty(builder, count, ordinal);
        nodes.push(std::array::from_fn(|i| builder.select(real, leaf[i], empty[i])));
    }
    for level in 1..=10 {
        nodes = nodes.chunks_exact(2)
            .map(|pair| deposit_leaf_node(builder, level, pair[0], pair[1])).collect();
    }
    nodes[0]
}

pub fn verify_deposit_leaf_path<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, active: BoolTarget, root: Bytes32Target,
    count: Target, ordinal: Target, leaf_commit: Bytes32Target,
    siblings: [Bytes32Target; 10],
) {
    builder.assert_bool(active);
    let zero = builder.zero();
    let selected_ordinal = builder.select(active, ordinal, zero);
    let bits = builder.split_le(selected_ordinal, 10);
    let in_range = builder.is_less_than(11, selected_ordinal, count);
    let outside = builder.not(in_range);
    let invalid = builder.mul(active.target, outside.target);
    builder.assert_zero(invalid);
    let inactive = builder.not(active);
    for word in leaf_commit.into_iter().chain(siblings.into_iter().flatten()) {
        builder.range_check(word, 32);
        let padding = builder.mul(inactive.target, word);
        builder.assert_zero(padding);
    }
    let mut node = deposit_leaf_node_leaf(builder, count, selected_ordinal, leaf_commit);
    for (level, sibling) in siblings.into_iter().enumerate() {
        let left = std::array::from_fn(|i| builder.select(bits[level], sibling[i], node[i]));
        let right = std::array::from_fn(|i| builder.select(bits[level], node[i], sibling[i]));
        node = deposit_leaf_node(builder, level as u8 + 1, left, right);
    }
    for i in 0..8 {
        builder.range_check(root[i], 32);
        let difference = builder.sub(node[i], root[i]);
        let invalid = builder.mul(active.target, difference);
        builder.assert_zero(invalid);
    }
}

/// Rows are canonical encoded A rows; inactive capacity rows must be all zero.
pub fn chain_rows_hash<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, variant: u8, first: Target,
    rows: &[Vec<Target>], count: Target,
) -> Bytes32Target {
    assert!(variant == 1 || variant == 2);
    assert!(rows.len() <= 256);
    let row_words = if variant == 1 { 152 } else { 232 };
    assert!(rows.iter().all(|row| row.len() == row_words));
    let family = builder.constant(F::from_canonical_u8(9));
    let variant = builder.constant(F::from_canonical_u8(variant));
    let mut header = word(builder, family, 16).to_vec();
    header.extend(word(builder, variant, 8));
    header.extend(word(builder, first, 32));
    header.extend(word(builder, count, 32));
    prefix_commitment(builder, Domain::LeafCommit, &header, rows, count, 0)
}

pub fn aggregate_leaf<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, family: u32, ordinal: Target, aggregate: Bytes32Target,
) -> Bytes32Target {
    assert!((1..=3).contains(&family));
    let family = builder.constant(F::from_canonical_u32(family));
    let mut body = word(builder, family, 8).to_vec();
    body.extend(word(builder, ordinal, 32));
    body.extend(aggregate);
    commitment(builder, Domain::Leaf, &body)
}

pub fn aggregate_empty<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, family: u32, ordinal: Target,
) -> Bytes32Target {
    assert!((1..=3).contains(&family));
    let family = builder.constant(F::from_canonical_u32(family));
    let mut body = word(builder, family, 8).to_vec();
    body.extend(word(builder, ordinal, 32));
    commitment(builder, Domain::Empty, &body)
}

pub fn aggregate_node<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, level: u8, left: Bytes32Target, right: Bytes32Target,
) -> Bytes32Target {
    assert!((1..=5).contains(&level));
    let level = builder.constant(F::from_canonical_u8(level));
    let mut body = word(builder, level, 8).to_vec();
    body.extend(left);
    body.extend(right);
    commitment(builder, Domain::Node, &body)
}


#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::{Field, Field64, PrimeField64}},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    fn native_hash(bytes: &[u8]) -> [u8; 32] {
        let mut hash = Keccak::v256();
        hash.update(bytes);
        let mut result = [0; 32];
        hash.finalize(&mut result);
        result
    }

    fn digest_bytes(public_inputs: &[F]) -> [u8; 32] {
        let mut bytes = [0; 32];
        for (i, value) in public_inputs.iter().enumerate() {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&(value.to_canonical_u64() as u32).to_be_bytes());
        }
        bytes
    }

    #[test]
    fn prefix_sponge_matches_host_at_rate_boundaries() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let words = builder.add_virtual_targets(68);
        let length = builder.add_virtual_target();
        let digest = keccak_prefix_words(&mut builder, &words, length);
        builder.register_public_inputs(&digest);
        let data = builder.build::<C>();
        // 135 exercises the combined 0x81 byte; 272 requires a new full padding block.
        for size in [0, 132, 135, 136, 137, 140, 272] {
            let bytes: Vec<u8> = (0..size).map(|i| (i * 17 + 3) as u8).collect();
            let mut padded = [0u8; 272];
            padded[..size].copy_from_slice(&bytes);
            let mut witness = PartialWitness::new();
            witness.set_target(length, F::from_canonical_usize(size)).unwrap();
            for (target, bytes) in words.iter().zip(padded.chunks_exact(4)) {
                witness.set_target(*target, F::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap()))).unwrap();
            }
            let proof = data.prove(witness).unwrap();
            assert_eq!(digest_bytes(&proof.public_inputs), native_hash(&bytes));
            data.verify(proof).unwrap();
        }
    }

    #[test]
    fn prefix_rejects_nonzero_padding_and_out_of_range_length() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let words = builder.add_virtual_targets(2);
        let length = builder.add_virtual_target();
        let digest = keccak_prefix_words(&mut builder, &words, length);
        builder.register_public_inputs(&digest);
        let data = builder.build::<C>();
        for (size, padding) in [(4u64, 1u32), (9, 0), (F::ORDER - 1, 0)] {
            let mut witness = PartialWitness::new();
            witness.set_target(length, F::from_canonical_u64(size)).unwrap();
            witness.set_target(words[0], F::ZERO).unwrap();
            witness.set_target(words[1], F::from_canonical_u32(padding)).unwrap();
            let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match data.prove(witness) { Ok(proof) => data.verify(proof).is_err(), Err(_) => true }
            }));
            assert!(rejected.unwrap_or(true));
        }
    }

    #[test]
    fn withdrawal_record_matches_host_word_grammar() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let targets = builder.add_virtual_targets(28);
        let leaf = WithdrawalLeafTarget {
            chain_index: targets[0], sender_user_id: targets[1],
            recipient: targets[2..7].try_into().unwrap(), token: targets[7..12].try_into().unwrap(),
            amount: targets[12..20].try_into().unwrap(), nonce: targets[20..28].try_into().unwrap(),
        };
        let digest = AggregateLeafTarget::Withdrawal(leaf).leaf_commit(&mut builder);
        builder.register_public_inputs(&digest);
        let data = builder.build::<C>();
        let mut values = [0u32; 28];
        values[0] = 7;
        values[1] = 0x12345678;
        for i in 2..28 { values[i] = 0x10203040 + i as u32; }
        for mutation in [false, true] {
            if mutation { values[27] ^= 1; }
            let mut body = Vec::new();
            body.extend(native_hash(b"PsyBridge/TwoArtifact/1/Record"));
            for (padding, source) in [
                (7, &[2u32][..]), (7, &values[0..1]), (7, &values[1..2]),
                (3, &values[2..7]), (3, &values[7..12]), (0, &values[12..20]), (0, &values[20..28]),
            ] {
                body.extend(vec![0; padding * 4]);
                for value in source { body.extend(value.to_be_bytes()); }
            }
            let mut witness = PartialWitness::new();
            for (target, value) in targets.iter().zip(values) {
                witness.set_target(*target, F::from_canonical_u32(value)).unwrap();
            }
            let proof = data.prove(witness).unwrap();
            assert_eq!(digest_bytes(&proof.public_inputs), native_hash(&body));
            data.verify(proof).unwrap();
        }
    }

    #[test]
    fn hash4_uses_four_canonical_big_endian_words() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let limbs: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        let encoded = encode_hash4(&mut builder, limbs);
        builder.register_public_inputs(&encoded);
        let data = builder.build::<C>();
        let values = [0, 0x0102030405060708, F::ORDER - 1, 17];
        let mut witness = PartialWitness::new();
        for (target, value) in limbs.into_iter().zip(values) {
            witness.set_target(target, F::from_canonical_u64(value)).unwrap();
        }
        let proof = data.prove(witness).unwrap();
        for (words, value) in proof.public_inputs.chunks_exact(8).zip(values) {
            assert!(words[..6].iter().all(|word| *word == F::ZERO));
            assert_eq!(words[6].to_canonical_u64(), value >> 32);
            assert_eq!(words[7].to_canonical_u64(), value & 0xffff_ffff);
        }
        data.verify(proof).unwrap();
    }

    #[test]
    fn chain_row_hash_matches_host_empty_and_real_prefix() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let first = builder.add_virtual_target();
        let count = builder.add_virtual_target();
        let row = builder.add_virtual_targets(152);
        let digest = chain_rows_hash(&mut builder, 1, first, &[row.clone()], count);
        builder.register_public_inputs(&digest);
        let data = builder.build::<C>();
        for active in [0usize, 1] {
            let mut witness = PartialWitness::new();
            witness.set_target(first, F::from_canonical_u32(7)).unwrap();
            witness.set_target(count, F::from_canonical_usize(active)).unwrap();
            let mut body = native_hash(b"PsyBridge/TwoArtifact/1/Record").to_vec();
            for value in [9u32, 1, 7, active as u32] {
                body.extend([0u8; 28]);
                body.extend(value.to_be_bytes());
            }
            for (i, &target) in row.iter().enumerate() {
                let value = if active == 1 { i as u32 + 1 } else { 0 };
                witness.set_target(target, F::from_canonical_u32(value)).unwrap();
                if active == 1 { body.extend(value.to_be_bytes()); }
            }
            let proof = data.prove(witness).unwrap();
            assert_eq!(digest_bytes(&proof.public_inputs), native_hash(&body));
            data.verify(proof).unwrap();
        }
    }

    #[test]
    fn deposit_leaf_root_matches_host_at_count_boundaries() {
        use psy_client_data::bridge_aggregate::deposit_leaf_tree;
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let commits: [Bytes32Target; 1024] = std::array::from_fn(|_| {
            builder.add_virtual_targets(8).try_into().unwrap()
        });
        let count = builder.add_virtual_target();
        let root = deposit_leaf_root(&mut builder, &commits, count);
        builder.register_public_inputs(&root);
        let data = builder.build::<C>();
        for size in [0usize, 1, 1023, 1024] {
            let records: Vec<_> = (0..size).map(|i| native_hash(&(i as u32).to_be_bytes())).collect();
            let tree = deposit_leaf_tree(&records).unwrap();
            let mut witness = PartialWitness::new();
            witness.set_target(count, F::from_canonical_usize(size)).unwrap();
            for (i, targets) in commits.iter().enumerate() {
                let bytes = records.get(i).copied().unwrap_or([0; 32]);
                for (target, bytes) in targets.iter().zip(bytes.chunks_exact(4)) {
                    witness.set_target(*target, F::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap()))).unwrap();
                }
            }
            let proof = data.prove(witness).unwrap();
            assert_eq!(digest_bytes(&proof.public_inputs), tree[0]);
            data.verify(proof).unwrap();
        }
    }

    #[test]
    fn deposit_path_rejects_wrong_position_count_and_sibling() {
        use psy_client_data::bridge_aggregate::{deposit_leaf_path, deposit_leaf_tree};
        let records = [native_hash(b"first deposit"), native_hash(b"second deposit")];
        let tree = deposit_leaf_tree(&records).unwrap();
        let path = deposit_leaf_path(&tree, 2, 1).unwrap();
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let active = builder.add_virtual_bool_target_safe();
        let root = constant_bytes32(&mut builder, tree[0]);
        let count = builder.add_virtual_target();
        let ordinal = builder.add_virtual_target();
        let record: Bytes32Target = builder.add_virtual_targets(8).try_into().unwrap();
        let siblings: [Bytes32Target; 10] = std::array::from_fn(|_| builder.add_virtual_targets(8).try_into().unwrap());
        verify_deposit_leaf_path(&mut builder, active, root, count, ordinal, record, siblings);
        let data = builder.build::<C>();
        // Inactive ordinal1024 must be selected away, not rejected by10-bit decomposition.
        for case in 0..7 {
            let enabled = case != 4 && case != 5;
            let index = match case { 1 => 0, 4 | 5 => 1024, 6 => 2, _ => 1 };
            let mut witness = PartialWitness::new();
            witness.set_bool_target(active, enabled).unwrap();
            witness.set_target(count, F::from_canonical_u32(if case == 2 { 3 } else { 2 })).unwrap();
            witness.set_target(ordinal, F::from_canonical_u32(index)).unwrap();
            let mut record_bytes = if enabled { records[1] } else { [0; 32] };
            if case == 5 { record_bytes[0] = 1; }
            for (target, bytes) in record.iter().zip(record_bytes.chunks_exact(4)) {
                witness.set_target(*target, F::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap()))).unwrap();
            }
            for (level, targets) in siblings.iter().enumerate() {
                let mut bytes = if enabled { path[level] } else { [0; 32] };
                if case == 3 && level == 0 { bytes[0] ^= 1; }
                for (target, bytes) in targets.iter().zip(bytes.chunks_exact(4)) {
                    witness.set_target(*target, F::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap()))).unwrap();
                }
            }
            let valid = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match data.prove(witness) { Ok(proof) => data.verify(proof).is_ok(), Err(_) => false }
            })).unwrap_or(false);
            assert_eq!(valid, case == 0 || case == 4);
        }
    }
}
