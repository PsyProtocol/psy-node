use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::{BoolTarget, Target}, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};
use psy_plonky2_basic_helpers::u32::{
    gadgets::{
        arithmetic_u32::{CircuitBuilderU32, U32Target},
        interleaved_u32::CircuitBuilderB32,
    },
    witness::WitnessU32,
};

// Keccak-f[1600] round constants split into [lo32, hi32] LE pairs.
#[rustfmt::skip]
const KECCAKF_RNDC: [[u32; 2]; 24] = [
    [0x00000001, 0x00000000], [0x00008082, 0x00000000],
    [0x0000808A, 0x80000000], [0x80008000, 0x80000000],
    [0x0000808B, 0x00000000], [0x80000001, 0x00000000],
    [0x80008081, 0x80000000], [0x00008009, 0x80000000],
    [0x0000008A, 0x00000000], [0x00000088, 0x00000000],
    [0x80008009, 0x00000000], [0x8000000A, 0x00000000],
    [0x8000808B, 0x00000000], [0x0000008B, 0x80000000],
    [0x00008089, 0x80000000], [0x00008003, 0x80000000],
    [0x00008002, 0x80000000], [0x00000080, 0x80000000],
    [0x0000800A, 0x00000000], [0x8000000A, 0x80000000],
    [0x80008081, 0x80000000], [0x00008080, 0x80000000],
    [0x80000001, 0x00000000], [0x80008008, 0x80000000],
];

// Rho rotation amounts (per lane index, as used in the pi-rho combined step).
#[rustfmt::skip]
const KECCAKF_ROTC: [u8; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

// Pi permutation lane indices.
#[rustfmt::skip]
const KECCAKF_PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

// Keccak state: 25 lanes, each represented as [lo_u32, hi_u32] (LE).
type KeccakState<'a> = &'a mut [[U32Target; 2]; 25];

/// Apply the Keccak-f[1600] permutation in-circuit (24 rounds).
pub fn keccak_f1600<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    s: &mut [[U32Target; 2]; 25],
) {
    let zero = builder.zero_u32();
    let mut bc = [[zero; 2]; 5];

    let rndc: [[U32Target; 2]; 24] = std::array::from_fn(|i| {
        [
            builder.constant_u32(KECCAKF_RNDC[i][0]),
            builder.constant_u32(KECCAKF_RNDC[i][1]),
        ]
    });

    for rndc_i in &rndc {
        // Theta
        for i in 0..5 {
            bc[i] = builder.unsafe_xor_many_u64(&[s[i], s[i + 5], s[i + 10], s[i + 15], s[i + 20]]);
        }
        for i in 0..5 {
            let t1 = builder.lrot_u64(&bc[(i + 1) % 5], 1);
            let t2 = builder.xor_u64(&bc[(i + 4) % 5], &t1);
            for j in 0..5 {
                s[5 * j + i] = builder.xor_u64(&s[5 * j + i], &t2);
            }
        }

        // Rho Pi (combined)
        let mut t = s[1];
        for i in 0..24 {
            let j = KECCAKF_PILN[i];
            let tmp = s[j];
            s[j] = builder.lrot_u64(&t, KECCAKF_ROTC[i]);
            t = tmp;
        }

        // Chi
        for j in 0..5 {
            for i in 0..5 {
                bc[i] = s[5 * j + i];
            }
            for i in 0..5 {
                let t1 = builder.not_u64(&bc[(i + 1) % 5]);
                let t2 = builder.and_u64(&bc[(i + 2) % 5], &t1);
                s[5 * j + i] = builder.xor_u64(&s[5 * j + i], &t2);
            }
        }

        // Iota
        s[0] = builder.xor_u64(&s[0], rndc_i);
    }
}

/// Keccak256 of a fixed 64-byte input (left[32] || right[32]), optimised for
/// the two-to-one Merkle use-case.
///
/// Input/output encoding: each `[U32Target; 8]` holds 32 bytes as 8 little-endian
/// 32-bit limbs (limb[0] = bytes 0-3, limb[7] = bytes 28-31).
///
/// This matches the encoding used by `Hash256` / `CoreKeccak256Hasher::two_to_one`
/// on the native Rust side, so proofs can be verified against on-chain
/// `keccak256(abi.encodePacked(left, right))`.
pub fn keccak256_two_to_one<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left: [U32Target; 8],
    right: [U32Target; 8],
) -> [U32Target; 8] {
    let mut input_bytes = Vec::with_capacity(64);
    for limb in left {
        input_bytes.extend(u32_target_to_bytes_le(builder, limb));
    }
    for limb in right {
        input_bytes.extend(u32_target_to_bytes_le(builder, limb));
    }
    keccak256_bytes_targets(builder, &input_bytes)
}

/// Keccak256 over a sequence of byte targets (one target per byte).
/// Each byte target is constrained to 8 bits by `split_le(target, 8)`.
/// Output is represented as 8 little-endian u32 limbs (`[u32; 8]`).
pub fn keccak256_bytes_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input_bytes: &[Target],
) -> [U32Target; 8] {
    let mut input_bits = Vec::with_capacity(input_bytes.len() * 8);
    for byte in input_bytes {
        let bits = builder.split_le(*byte, 8);
        input_bits.extend(bits);
    }

    let output_bits = keccak256_bits(input_bits, builder);
    std::array::from_fn(|i| U32Target(bits_le_to_target(&output_bits[i * 32..(i + 1) * 32], builder)))
}

/// Keccak256 over a sequence of u32 words where each word is encoded as
/// big-endian bytes (`abi.encodePacked(uint32, ...)` semantics).
pub fn keccak256_u32_words_be_abi<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input_words_u32: &[Target],
) -> [U32Target; 8] {
    let mut input_bytes = Vec::with_capacity(input_words_u32.len() * 4);
    for target in input_words_u32 {
        let limb = U32Target(*target);
        let bytes_le = u32_target_to_bytes_le(builder, limb);
        // abi uint32 uses big-endian bytes.
        input_bytes.push(bytes_le[3]);
        input_bytes.push(bytes_le[2]);
        input_bytes.push(bytes_le[1]);
        input_bytes.push(bytes_le[0]);
    }
    let out_le = keccak256_bytes_targets(builder, &input_bytes);
    std::array::from_fn(|i| {
        let bytes_le = u32_target_to_bytes_le(builder, out_le[i]);
        // Convert LE limb representation to BE limb representation for bytes32-style consumers.
        let b0_bits = builder.split_le(bytes_le[0], 8);
        let b1_bits = builder.split_le(bytes_le[1], 8);
        let b2_bits = builder.split_le(bytes_le[2], 8);
        let b3_bits = builder.split_le(bytes_le[3], 8);
        let mut bits = Vec::with_capacity(32);
        bits.extend(b3_bits);
        bits.extend(b2_bits);
        bits.extend(b1_bits);
        bits.extend(b0_bits);
        U32Target(bits_le_to_target(&bits, builder))
    })
}

fn bits_le_to_target<F, const D: usize>(bits: &[BoolTarget], builder: &mut CircuitBuilder<F, D>) -> Target
where
    F: RichField + Extendable<D>,
{
    let mut sum = builder.zero();
    let mut power_of_two = builder.one();
    for bit in bits {
        sum = builder.mul_add(bit.target, power_of_two, sum);
        power_of_two = builder.add(power_of_two, power_of_two);
    }
    sum
}

fn u32_target_to_bytes_le<F, const D: usize>(builder: &mut CircuitBuilder<F, D>, x: U32Target) -> [Target; 4]
where
    F: RichField + Extendable<D>,
{
    let bits = builder.split_le(x.0, 32);
    [
        bits_le_to_target(&bits[0..8], builder),
        bits_le_to_target(&bits[8..16], builder),
        bits_le_to_target(&bits[16..24], builder),
        bits_le_to_target(&bits[24..32], builder),
    ]
}

fn keccak256_bits<F, const D: usize>(input: Vec<BoolTarget>, builder: &mut CircuitBuilder<F, D>) -> Vec<BoolTarget>
where
    F: RichField + Extendable<D>,
{
    assert_eq!(input.len() % 8, 0);
    let block_size_in_bytes = 136;
    let input_len_in_bytes = input.len() / 8;
    let num_blocks = input_len_in_bytes / block_size_in_bytes + 1;

    let mut padded = vec![];
    for _ in 0..block_size_in_bytes * 8 * num_blocks {
        padded.push(builder.add_virtual_bool_target_safe());
    }

    for i in 0..input_len_in_bytes * 8 {
        builder.connect(padded[i].target, input[i].target);
    }

    let true_target = builder.constant_bool(true);
    builder.connect(padded[input_len_in_bytes * 8].target, true_target.target);

    let false_target = builder.constant_bool(false);
    let last_index = padded.len() - 1;
    for i in input_len_in_bytes * 8 + 1..last_index {
        builder.connect(padded[i].target, false_target.target);
    }
    builder.connect(padded[last_index].target, true_target.target);

    // State as bits to stay compatible with the current DPN opcode path.
    let mut state_bits = vec![false_target; 1600];

    for block_idx in 0..num_blocks {
        for j in 0..block_size_in_bytes * 8 {
            let idx = block_idx * block_size_in_bytes * 8 + j;
            let state_plus_input = builder.add(state_bits[j].target, padded[idx].target);
            // XOR over booleans is x + y - 2xy.
            // Using x + y - xy would implement OR, which only matches XOR when one input is zero.
            state_bits[j] = BoolTarget::new_unsafe(builder.arithmetic(
                -F::TWO,
                F::ONE,
                state_bits[j].target,
                padded[idx].target,
                state_plus_input,
            ));
        }

        // Convert bit-state into lane-state and apply permutation.
        let mut lanes = [[builder.zero_u32(); 2]; 25];
        for lane in 0..25 {
            let lane_bits = &state_bits[lane * 64..(lane + 1) * 64];
            lanes[lane][0] = U32Target(bits_le_to_target(&lane_bits[0..32], builder));
            lanes[lane][1] = U32Target(bits_le_to_target(&lane_bits[32..64], builder));
        }
        keccak_f1600(builder, &mut lanes);
        for lane in 0..25 {
            let lo_bits = builder.split_le(lanes[lane][0].0, 32);
            let hi_bits = builder.split_le(lanes[lane][1].0, 32);
            for i in 0..32 {
                state_bits[lane * 64 + i] = lo_bits[i];
                state_bits[lane * 64 + 32 + i] = hi_bits[i];
            }
        }
    }

    state_bits[0..256].to_vec()
}

/// Witness helper: set a `[U32Target; 8]` from a 32-byte slice (LE u32 limbs).
pub fn set_hash256_target<F: RichField, W: Witness<F>>(
    pw: &mut W,
    targets: &[U32Target; 8],
    bytes: &[u8; 32],
) -> anyhow::Result<()> {
    for i in 0..8 {
        let v = u32::from_le_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap());
        pw.set_u32_target(targets[i], v)?;
    }
    Ok(())
}

/// Read a `[U32Target; 8]` back as a 32-byte array (LE u32 limbs).
pub fn read_hash256_target<F: RichField, W: Witness<F>>(
    pw: &W,
    targets: &[U32Target; 8],
) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        let (lo, _) = pw.get_u32_target(targets[i]);
        out[i * 4..(i + 1) * 4].copy_from_slice(&lo.to_le_bytes());
    }
    out
}

/// Virtual `[U32Target; 8]` (Hash256 target).
pub fn add_virtual_hash256_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> [U32Target; 8] {
    std::array::from_fn(|_| builder.add_virtual_u32_target())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tiny_keccak::{Hasher, Keccak};
    use plonky2::{
        field::types::Field,
        field::types::PrimeField64,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use psy_plonky2_basic_helpers::u32::witness::WitnessU32;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    fn native_keccak256_helper(data: &[u8]) -> [u8; 32] {
        let mut h = Keccak::v256();
        h.update(data);
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        out
    }

    #[test]
    fn test_keccak256_two_to_one_matches_native() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&left);
        input[32..].copy_from_slice(&right);
        let expected = native_keccak256_helper(&input);

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let left_t = add_virtual_hash256_target(&mut builder);
        let right_t = add_virtual_hash256_target(&mut builder);
        let out_t = keccak256_two_to_one(&mut builder, left_t, right_t);

        // Register output as public inputs so we can inspect them
        for t in &out_t {
            builder.register_public_input(t.0);
        }

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        set_hash256_target(&mut pw, &left_t, &left).unwrap();
        set_hash256_target(&mut pw, &right_t, &right).unwrap();

        let proof = data.prove(pw).expect("prove failed");
        data.verify(proof.clone()).expect("verify failed");

        // Extract output from public inputs
        let mut got = [0u8; 32];
        for i in 0..8 {
            let v = proof.public_inputs[i].to_canonical_u64() as u32;
            got[i * 4..(i + 1) * 4].copy_from_slice(&v.to_le_bytes());
        }
        assert_eq!(got, expected, "circuit output does not match native keccak256");
    }

    #[test]
    fn test_keccak256_bytes_targets_matches_native() {
        let input: Vec<u8> = vec![0x01, 0x23, 0x45, 0x67, 0x89];
        let expected = native_keccak256_helper(&input);

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut input_t = Vec::with_capacity(input.len());
        for _ in 0..input.len() {
            input_t.push(builder.add_virtual_target());
        }
        let out_t = keccak256_bytes_targets(&mut builder, &input_t);
        for t in &out_t {
            builder.register_public_input(t.0);
        }

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        for (i, b) in input.iter().enumerate() {
            pw.set_target(input_t[i], F::from_canonical_u64(*b as u64));
        }
        let proof = data.prove(pw).expect("prove failed");
        data.verify(proof.clone()).expect("verify failed");

        let mut got = [0u8; 32];
        for i in 0..8 {
            let v = proof.public_inputs[i].to_canonical_u64() as u32;
            got[i * 4..(i + 1) * 4].copy_from_slice(&v.to_le_bytes());
        }
        assert_eq!(got, expected, "bytes keccak output does not match native keccak256");
    }

    #[test]
    fn test_keccak256_u32_words_be_abi_matches_native_multi_block() {
        let input_words: Vec<u32> = vec![
            16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
            32, 33, 34, 35, 36, 37, 38, 39,
            40, 41, 42, 43, 44, 45, 46, 47,
            1, 0, 2,
        ];
        let mut input_bytes = Vec::with_capacity(input_words.len() * 4);
        for w in &input_words {
            input_bytes.extend_from_slice(&w.to_be_bytes());
        }
        let expected = native_keccak256_helper(&input_bytes);

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut input_t = Vec::with_capacity(input_words.len());
        for _ in 0..input_words.len() {
            input_t.push(builder.add_virtual_target());
        }
        let out_t = keccak256_u32_words_be_abi(&mut builder, &input_t);
        for t in &out_t {
            builder.register_public_input(t.0);
        }

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        for (i, w) in input_words.iter().enumerate() {
            pw.set_target(input_t[i], F::from_canonical_u64(*w as u64));
        }
        let proof = data.prove(pw).expect("prove failed");
        data.verify(proof.clone()).expect("verify failed");

        let mut got_be = [0u8; 32];
        for i in 0..8 {
            let v = proof.public_inputs[i].to_canonical_u64() as u32;
            got_be[i * 4..(i + 1) * 4].copy_from_slice(&v.to_be_bytes());
        }
        assert_eq!(
            got_be, expected,
            "multi-block u32 abi keccak output does not match native keccak256"
        );
    }
}
