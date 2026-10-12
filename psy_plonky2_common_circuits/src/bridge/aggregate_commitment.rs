use plonky2::{
    field::extension::Extendable,
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use tiny_keccak::{Hasher, Keccak};
use psy_client_data::bridge_aggregate::{
    DEPOSIT_ACCUMULATOR_SEED_DOMAIN, DEPOSIT_ACCUMULATOR_FOLD_DOMAIN,
};

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

/// Full partial-XOR state; each lane is [low u32, high u32].
#[derive(Clone, Copy)]
pub struct KeccakStreamTargets {
    pub state: [[U32Target; 2]; 25],
    pub byte_offset: Target,
}

#[derive(Clone, Copy, Default)]
pub struct KeccakStreamValues {
    pub state: [[u32; 2]; 25],
    pub byte_offset: u8,
}

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

impl DepositLeafTarget {
    pub fn poseidon_hash<F: RichField + Extendable<D>, const D: usize>(
        &self, builder: &mut CircuitBuilder<F, D>,
    ) -> Hash4Target {
        let mut fields = Vec::with_capacity(41);
        fields.extend(self.shield_address);
        fields.extend(word_address(builder, self.token));
        fields.extend(self.l2_token_contract_id);
        fields.extend(self.amount);
        fields.push(self.chain_index);
        fields.extend(self.note_commitment);
        builder.hash_n_to_hash_no_pad::<PoseidonHash>(fields).elements
    }
}

pub fn deposit_accumulator_seed<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, config_hash: Bytes32Target,
    end_checkpoint_id: U64Target, end_checkpoint_root: Hash4Target,
    global_deposit_count: Target,
) -> Hash4Target {
    let mut fields = Vec::with_capacity(16);
    fields.push(builder.constant(F::from_canonical_u64(DEPOSIT_ACCUMULATOR_SEED_DOMAIN)));
    fields.extend(config_hash);
    fields.extend(end_checkpoint_id);
    fields.extend(end_checkpoint_root);
    fields.push(global_deposit_count);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(fields).elements
}

pub fn deposit_accumulator_fold<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, accumulator: Hash4Target, ordinal: Target,
    chain_index: Target, absolute_index: Target, leaf_hash: Hash4Target,
) -> Hash4Target {
    let mut fields = Vec::with_capacity(12);
    fields.push(builder.constant(F::from_canonical_u64(DEPOSIT_ACCUMULATOR_FOLD_DOMAIN)));
    fields.extend(accumulator);
    fields.extend([ordinal, chain_index, absolute_index]);
    fields.extend(leaf_hash);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(fields).elements
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

/// Append a zero-tailed big-endian word prefix without final padding.
pub fn keccak_stream_absorb<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, stream: KeccakStreamTargets,
    words: &[Target; 34], byte_length: Target,
) -> KeccakStreamTargets {
    for half in stream.state.iter().flatten() {
        builder.range_check(half.0, 32);
    }
    let offset_bits = builder.split_le(stream.byte_offset, 8);
    let last = builder.constant(F::from_canonical_usize(135));
    builder.ensure_is_less_than_or_equal(8, stream.byte_offset, last);
    builder.range_check(byte_length, 8);
    let rate = builder.constant(F::from_canonical_usize(136));
    builder.ensure_is_less_than_or_equal(8, byte_length, rate);
    let zero = builder.zero();
    let mut shifted = [zero; 272];
    for (i, &word) in words.iter().enumerate() {
        let bits = builder.split_le(word, 32);
        for byte in 0..4 {
            let start = (3 - byte) * 8;
            let value = builder.le_sum(bits[start..start + 8].iter());
            let index = builder.constant(F::from_canonical_usize(i * 4 + byte));
            let real = builder.is_less_than(8, index, byte_length);
            let inactive = builder.not(real);
            let suffix = builder.mul(inactive.target, value);
            builder.assert_zero(suffix);
            shifted[i * 4 + byte] = value;
        }
    }
    for (bit, &enabled) in offset_bits.iter().enumerate() {
        shifted = std::array::from_fn(|j| {
            let source = if j >= 1 << bit { shifted[j - (1 << bit)] } else { zero };
            builder.select(enabled, source, shifted[j])
        });
    }
    let mut state = stream.state;
    for half in 0..34 {
        let mut word = zero;
        for byte in (0..4).rev() {
            word = builder.mul_const_add(F::from_canonical_u32(256), word, shifted[half * 4 + byte]);
        }
        state[half / 2][half % 2] = xor_u32_bounded(builder, state[half / 2][half % 2], U32Target(word));
    }
    let mut permuted = state;
    keccak_f1600(builder, &mut permuted);
    let sum = builder.add(stream.byte_offset, byte_length);
    let full = builder.is_greater_than_or_equal(9, sum, rate);
    for lane in 0..25 {
        for half in 0..2 {
            state[lane][half] = U32Target(builder.select(full, permuted[lane][half].0, state[lane][half].0));
        }
    }
    for half in 0..34 {
        let mut word = zero;
        for byte in (0..4).rev() {
            word = builder.mul_const_add(F::from_canonical_u32(256), word, shifted[136 + half * 4 + byte]);
        }
        state[half / 2][half % 2] = xor_u32_bounded(builder, state[half / 2][half % 2], U32Target(word));
    }
    let byte_offset = builder.mul_const_add(-F::from_canonical_usize(136), full.target, sum);
    KeccakStreamTargets { state, byte_offset }
}

pub fn keccak_stream_finalize<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, stream: KeccakStreamTargets,
) -> Bytes32Target {
    for half in stream.state.iter().flatten() {
        builder.range_check(half.0, 32);
    }
    builder.range_check(stream.byte_offset, 8);
    let last = builder.constant(F::from_canonical_usize(135));
    builder.ensure_is_less_than_or_equal(8, stream.byte_offset, last);
    let zero = builder.zero();
    let padding: [Target; 136] = std::array::from_fn(|j| {
        let index = builder.constant(F::from_canonical_usize(j));
        let start = builder.is_equal(stream.byte_offset, index);
        if j == 135 {
            builder.add_const(start.target, F::from_canonical_u8(128))
        } else {
            start.target
        }
    });
    let mut state = stream.state;
    for half in 0..34 {
        let mut word = zero;
        for byte in (0..4).rev() {
            word = builder.mul_const_add(F::from_canonical_u32(256), word, padding[half * 4 + byte]);
        }
        state[half / 2][half % 2] = xor_u32_bounded(builder, state[half / 2][half % 2], U32Target(word));
    }
    keccak_f1600(builder, &mut state);
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

pub fn keccak_stream_absorb_values(
    stream: &mut KeccakStreamValues, words: &[u32; 34], byte_length: usize,
) -> anyhow::Result<()> {
    anyhow::ensure!(stream.byte_offset < 136, "Keccak stream offset exceeds rate");
    anyhow::ensure!(byte_length <= 136, "Keccak stream length exceeds rate");
    let bytes: [u8; 136] = std::array::from_fn(|i| words[i / 4].to_be_bytes()[i % 4]);
    anyhow::ensure!(bytes[byte_length..].iter().all(|&byte| byte == 0), "Keccak stream suffix is nonzero");
    let mut lanes: [u64; 25] = std::array::from_fn(|i| stream.state[i][0] as u64 | ((stream.state[i][1] as u64) << 32));
    let mut offset = stream.byte_offset as usize;
    for &byte in &bytes[..byte_length] {
        lanes[offset / 8] ^= (byte as u64) << (8 * (offset % 8));
        offset += 1;
        if offset == 136 {
            tiny_keccak::keccakf(&mut lanes);
            offset = 0;
        }
    }
    stream.state = std::array::from_fn(|i| [lanes[i] as u32, (lanes[i] >> 32) as u32]);
    stream.byte_offset = offset as u8;
    Ok(())
}

pub fn keccak_stream_finalize_values(stream: KeccakStreamValues) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(stream.byte_offset < 136, "Keccak stream offset exceeds rate");
    let mut lanes: [u64; 25] = std::array::from_fn(|i| stream.state[i][0] as u64 | ((stream.state[i][1] as u64) << 32));
    let offset = stream.byte_offset as usize;
    lanes[offset / 8] ^= 1u64 << (8 * (offset % 8));
    lanes[16] ^= 0x80u64 << 56;
    tiny_keccak::keccakf(&mut lanes);
    Ok(std::array::from_fn(|i| lanes[i / 8].to_le_bytes()[i % 8]))
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

    #[test]
    fn deposit_poseidon_helpers_match_native_encodings() {
        use psy_client_data::bridge_aggregate as native;
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let config = std::array::from_fn(|i| i as u8);
        let checkpoint_id = 0x123456789abcdef0u64;
        let checkpoint_root = [0, 1, 1u64 << 32, native::GOLDILOCKS_MODULUS - 1];
        let config_target = constant_bytes32(&mut builder, config);
        let id_target = [checkpoint_id as u32, (checkpoint_id >> 32) as u32]
            .map(|value| builder.constant(F::from_canonical_u32(value)));
        let root_target = checkpoint_root.map(|value| builder.constant(F::from_canonical_u64(value)));
        let count = builder.constant(F::from_canonical_u32(1024));
        let seed = deposit_accumulator_seed(&mut builder, config_target, id_target, root_target, count);
        let native_seed = native::deposit_accumulator_seed(config, checkpoint_id, checkpoint_root, 1024).unwrap();
        let leaf = native::DepositLeaf {
            chain_index: 255, absolute_index: u32::MAX - 1, shield_address: [0x81; 32],
            token: [0x42; 20], l2_token_contract_id: [0x23; 32], amount: [0xff; 32],
            note_commitment: [0x54; 32],
        };
        let leaf_target = DepositLeafTarget {
            chain_index: builder.constant(F::from_canonical_u8(leaf.chain_index)),
            absolute_index: builder.constant(F::from_canonical_u32(leaf.absolute_index)),
            shield_address: constant_bytes32(&mut builder, leaf.shield_address),
            token: std::array::from_fn(|i| builder.constant(F::from_canonical_u32(
                u32::from_be_bytes(leaf.token[i * 4..i * 4 + 4].try_into().unwrap())))),
            l2_token_contract_id: constant_bytes32(&mut builder, leaf.l2_token_contract_id),
            amount: constant_bytes32(&mut builder, leaf.amount),
            note_commitment: constant_bytes32(&mut builder, leaf.note_commitment),
        };
        AggregateLeafTarget::Deposit(leaf_target).encode(&mut builder);
        let leaf_hash = leaf_target.poseidon_hash(&mut builder);
        let ordinal = builder.constant(F::from_canonical_u32(1023));
        let folded = deposit_accumulator_fold(&mut builder, seed, ordinal,
            leaf_target.chain_index, leaf_target.absolute_index, leaf_hash);
        for output in [seed, leaf_hash, folded] {
            builder.register_public_inputs(&output);
        }
        let data = builder.build::<C>();
        let proof = data.prove(PartialWitness::new()).unwrap();
        let expected = [native_seed, leaf.poseidon_hash().unwrap(),
            native::deposit_accumulator_fold(native_seed, 1023, leaf.chain_index,
                leaf.absolute_index, leaf.poseidon_hash().unwrap()).unwrap()];
        assert_eq!(proof.public_inputs, expected.into_iter().flatten()
            .map(F::from_canonical_u64).collect::<Vec<_>>());
        data.verify(proof).unwrap();
    }

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

    fn stream_words(bytes: &[u8]) -> [u32; 34] {
        let mut block = [0u8; 136];
        block[..bytes.len()].copy_from_slice(bytes);
        std::array::from_fn(|i| u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap()))
    }

    fn stream_targets(builder: &mut CircuitBuilder<F, 2>) -> KeccakStreamTargets {
        KeccakStreamTargets {
            state: std::array::from_fn(|_| std::array::from_fn(|_| U32Target(builder.add_virtual_target()))),
            byte_offset: builder.add_virtual_target(),
        }
    }

    fn set_stream(witness: &mut PartialWitness<F>, targets: KeccakStreamTargets, values: KeccakStreamValues) {
        for (target, value) in targets.state.iter().flatten().zip(values.state.iter().flatten()) {
            witness.set_target(target.0, F::from_canonical_u32(*value)).unwrap();
        }
        witness.set_target(targets.byte_offset, F::from_canonical_u8(values.byte_offset)).unwrap();
    }

    #[test]
    fn stream_native_digest_boundaries_and_error_atomicity() {
        for size in [0, 1, 4, 135, 136, 137, 271, 272, 288] {
            let bytes: Vec<u8> = (0..size).map(|i| (i * 17 + 1) as u8).collect();
            for width in [1, 135, 136] {
                let mut stream = KeccakStreamValues::default();
                for part in bytes.chunks(width) {
                    keccak_stream_absorb_values(&mut stream, &stream_words(part), part.len()).unwrap();
                }
                assert_eq!(keccak_stream_finalize_values(stream).unwrap(), native_hash(&bytes));
            }
        }
        let mut endian = KeccakStreamValues::default();
        keccak_stream_absorb_values(&mut endian, &stream_words(&[1, 2, 3, 4]), 4).unwrap();
        assert_eq!(endian.state[0], [0x04030201, 0]);
        assert_eq!(endian.byte_offset, 4);
        let state = std::array::from_fn(|i| [0x89abcdefu32.wrapping_mul(i as u32 + 1), 0xfedcba98 ^ i as u32]);
        for offset in [0, 1, 135] {
            let mut stream = KeccakStreamValues { state, byte_offset: offset };
            keccak_stream_absorb_values(&mut stream, &[0; 34], 0).unwrap();
            assert_eq!(stream.state, state);
            assert_eq!(stream.byte_offset, offset);
        }
        for (offset, length, suffix) in [(136, 0, None), (255, 0, None), (1, 137, None), (1, usize::MAX, None), (1, 0, Some(0)), (1, 1, Some(1)), (1, 24, Some(135))] {
            let mut stream = KeccakStreamValues { state, byte_offset: offset };
            let mut bytes = [0u8; 136];
            if let Some(index) = suffix { bytes[index] = 1; }
            assert!(keccak_stream_absorb_values(&mut stream, &stream_words(&bytes), length).is_err());
            assert_eq!(stream.state, state);
            assert_eq!(stream.byte_offset, offset);
        }
        for offset in [136, 255] {
            assert!(keccak_stream_finalize_values(KeccakStreamValues { state, byte_offset: offset }).is_err());
        }
    }

    #[test]
    fn stream_absorb_preserves_arbitrary_state_and_crosses_rate() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let input = stream_targets(&mut builder);
        let words: [Target; 34] = builder.add_virtual_targets(34).try_into().unwrap();
        let length = builder.add_virtual_target();
        let output = keccak_stream_absorb(&mut builder, input, &words, length);
        for half in output.state.iter().flatten() { builder.register_public_input(half.0); }
        builder.register_public_input(output.byte_offset);
        let data = builder.build::<C>();
        for (offset, size) in [(0, 0), (1, 0), (135, 0), (0, 1), (1, 1), (0, 136), (1, 136), (135, 1), (135, 136)] {
            let input_values = KeccakStreamValues {
                state: std::array::from_fn(|i| [0x89abcdefu32.wrapping_mul(i as u32 + 1), 0xfedcba98 ^ i as u32]),
                byte_offset: offset,
            };
            let bytes: Vec<u8> = (0..size).map(|i| (i * 17 + 1) as u8).collect();
            let mut expected = input_values;
            keccak_stream_absorb_values(&mut expected, &stream_words(&bytes), size).unwrap();
            let mut witness = PartialWitness::new();
            set_stream(&mut witness, input, input_values);
            witness.set_target(length, F::from_canonical_usize(size)).unwrap();
            for (target, word) in words.iter().zip(stream_words(&bytes)) {
                witness.set_target(*target, F::from_canonical_u32(word)).unwrap();
            }
            let proof = data.prove(witness).unwrap();
            for (value, half) in proof.public_inputs[..50].iter().zip(expected.state.iter().flatten()) {
                assert_eq!(value.to_canonical_u64(), *half as u64);
            }
            assert_eq!(proof.public_inputs[50].to_canonical_u64(), expected.byte_offset as u64);
            data.verify(proof).unwrap();
        }
    }

    #[test]
    fn stream_circuit_matches_native_multiblock() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let zero = builder.zero();
        let mut stream = KeccakStreamTargets { state: [[U32Target(zero); 2]; 25], byte_offset: zero };
        let words: [[Target; 34]; 3] = std::array::from_fn(|_| builder.add_virtual_targets(34).try_into().unwrap());
        let lengths: [Target; 3] = std::array::from_fn(|_| builder.add_virtual_target());
        for i in 0..3 {
            stream = keccak_stream_absorb(&mut builder, stream, &words[i], lengths[i]);
        }
        let digest = keccak_stream_finalize(&mut builder, stream);
        builder.register_public_inputs(&digest);
        let data = builder.build::<C>();
        for (size, first_size) in [(0, 0), (1, 1), (4, 4), (135, 135), (136, 136), (136, 135), (137, 136), (271, 135), (272, 136), (288, 136), (288, 135)] {
            let bytes: Vec<u8> = (0..size).map(|i| (i * 17 + 1) as u8).collect();
            let mut values = KeccakStreamValues::default();
            let mut witness = PartialWitness::new();
            let mut start = 0;
            for i in 0..3 {
                let end = if i == 0 { first_size } else { (start + 136).min(size) };
                let part = &bytes[start..end];
                let block = stream_words(part);
                keccak_stream_absorb_values(&mut values, &block, part.len()).unwrap();
                witness.set_target(lengths[i], F::from_canonical_usize(part.len())).unwrap();
                for (target, word) in words[i].iter().zip(block) {
                    witness.set_target(*target, F::from_canonical_u32(word)).unwrap();
                }
                start = end;
            }
            assert_eq!(start, size);
            let proof = data.prove(witness).unwrap();
            assert_eq!(digest_bytes(&proof.public_inputs), keccak_stream_finalize_values(values).unwrap());
            assert_eq!(digest_bytes(&proof.public_inputs), native_hash(&bytes));
            data.verify(proof).unwrap();
        }
    }

    #[test]
    fn stream_rejects_suffix_endpoint_and_bound_digest_mutations() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let first = stream_targets(&mut builder);
        let words: [Target; 34] = builder.add_virtual_targets(34).try_into().unwrap();
        let length = builder.add_virtual_target();
        let second = keccak_stream_absorb(&mut builder, first, &words, length);
        let witnessed = stream_targets(&mut builder);
        for (expected, supplied) in second.state.iter().flatten().zip(witnessed.state.iter().flatten()) {
            builder.connect(expected.0, supplied.0);
        }
        builder.connect(second.byte_offset, witnessed.byte_offset);
        let suffix_words: [Target; 34] = builder.add_virtual_targets(34).try_into().unwrap();
        let suffix_length = builder.add_virtual_target();
        let third = keccak_stream_absorb(&mut builder, witnessed, &suffix_words, suffix_length);
        let digest = keccak_stream_finalize(&mut builder, third);
        let expected_digest: Bytes32Target = builder.add_virtual_targets(8).try_into().unwrap();
        for (actual, expected) in digest.iter().zip(expected_digest) { builder.connect(*actual, expected); }
        builder.register_public_inputs(&digest);
        let data = builder.build::<C>();
        let message: [u8; 272] = std::array::from_fn(|i| (i * 17 + 1) as u8);
        let mut middle = KeccakStreamValues::default();
        keccak_stream_absorb_values(&mut middle, &stream_words(&message[..136]), 136).unwrap();
        let digest_bytes = native_hash(&message);
        let mut digest_words = [0u32; 8];
        for (word, bytes) in digest_words.iter_mut().zip(digest_bytes.chunks_exact(4)) {
            *word = u32::from_be_bytes(bytes.try_into().unwrap());
        }
        let head: [u8; 136] = message[..136].try_into().unwrap();
        let suffix: [u8; 136] = message[136..].try_into().unwrap();
        for index in 0..6 {
            let mut endpoint = middle;
            let mut suffix = suffix;
            let suffix_size = if index == 4 { 135 } else { 136 };
            if index == 1 { endpoint.state[0][0] ^= 1; }
            if index == 2 { endpoint.state[24][1] ^= 1; }
            if index == 3 { endpoint.byte_offset += 1; }
            if index == 5 { suffix[0] ^= 1; }
            let mut witness = PartialWitness::new();
            set_stream(&mut witness, first, KeccakStreamValues::default());
            set_stream(&mut witness, witnessed, endpoint);
            witness.set_target(length, F::from_canonical_usize(136)).unwrap();
            witness.set_target(suffix_length, F::from_canonical_usize(suffix_size)).unwrap();
            for (target, word) in words.iter().zip(stream_words(&head)) {
                witness.set_target(*target, F::from_canonical_u32(word)).unwrap();
            }
            for (target, word) in suffix_words.iter().zip(stream_words(&suffix)) {
                witness.set_target(*target, F::from_canonical_u32(word)).unwrap();
            }
            for (target, word) in expected_digest.iter().zip(digest_words) {
                witness.set_target(*target, F::from_canonical_u32(word)).unwrap();
            }
            let valid = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match data.prove(witness) { Ok(proof) => data.verify(proof).is_ok(), Err(_) => false }
            })).unwrap_or(false);
            assert_eq!(valid, index == 0);
        }
    }

    #[test]
    fn stream_rejects_malformed_state_scalars_words_and_zero_tail() {
        for finalize_only in [false, true] {
            let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
            let input = stream_targets(&mut builder);
            let words: [Target; 34] = builder.add_virtual_targets(34).try_into().unwrap();
            let length = builder.add_virtual_target();
            let stream = if finalize_only { input } else { keccak_stream_absorb(&mut builder, input, &words, length) };
            let digest = keccak_stream_finalize(&mut builder, stream);
            builder.register_public_inputs(&digest);
            let data = builder.build::<C>();
            // Case zero must verify before any rejection can count as evidence.
            for case in 0..if finalize_only { 7 } else { 13 } {
                let mut witness = PartialWitness::new();
                for (index, half) in input.state.iter().flatten().enumerate() {
                    let oversized = match case { 3 => index == 0, 4 => index == 1, 5 => index == 48, 6 => index == 49, _ => false };
                    witness.set_target(half.0, F::from_canonical_u64(if oversized { 1u64 << 32 } else { 0 })).unwrap();
                }
                let offset = match case { 1 => 136, 2 => F::ORDER - 1, _ => 0 };
                let size = match case { 7 => 137, 8 => F::ORDER - 1, 11 => 1, 12 => 24, _ => 0 };
                witness.set_target(input.byte_offset, F::from_canonical_u64(offset)).unwrap();
                witness.set_target(length, F::from_canonical_u64(size)).unwrap();
                for (index, &word) in words.iter().enumerate() {
                    let value = match (case, index) {
                        (9, 0) => 1u64 << 32,
                        (10, 0) => 0x01000000,
                        (11, 0) => 0x00010000,
                        (12, 33) => 1,
                        _ => 0,
                    };
                    witness.set_target(word, F::from_canonical_u64(value)).unwrap();
                }
                let valid = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    match data.prove(witness) { Ok(proof) => data.verify(proof).is_ok(), Err(_) => false }
                })).unwrap_or(false);
                assert_eq!(valid, case == 0, "finalize_only={finalize_only}, case={case}");
            }
        }
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
}
