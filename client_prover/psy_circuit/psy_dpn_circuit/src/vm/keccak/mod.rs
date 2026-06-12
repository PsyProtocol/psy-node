use psy_plonky2_common_circuits::hash::keccak::keccak256_u32_words_be_abi;

#[cfg(test)]
mod tests {
    use alloy_primitives::{FixedBytes, B256};
    use alloy_sol_types::SolValue;
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{Field, PrimeField64},
        },
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use tiny_keccak::{Hasher as _, Keccak};

    use super::keccak256_u32_words_be_abi;

    fn keccak_digest_bytes_to_u32x8(bytes: &[u8]) -> [u32; 8] {
        let mut digest = [0u8; 32];
        let mut keccak = Keccak::v256();
        keccak.update(bytes);
        keccak.finalize(&mut digest);
        let mut out = [0u32; 8];
        for i in 0..8 {
            out[i] = u32::from_be_bytes(digest[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        out
    }

    #[test]
    fn tiny_keccak_alloy_and_circuit_match_for_bytes32_pair() {
        type F = GoldilocksField;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;

        let left = B256::from_slice(&hex::decode("dacbc08f57113157b1caed6257112dec8fc0cbdaaf661252a0216b1c95d5ed65").unwrap());
        let right = B256::ZERO;

        let packed = (left, right).abi_encode_packed();
        let expected = keccak_digest_bytes_to_u32x8(&packed);

        let left_bytes = left.as_slice();
        let right_bytes = right.as_slice();
        let mut limbs = [0u32; 16];
        for i in 0..8 {
            limbs[i] = u32::from_be_bytes(left_bytes[i * 4..(i + 1) * 4].try_into().unwrap());
            limbs[i + 8] = u32::from_be_bytes(right_bytes[i * 4..(i + 1) * 4].try_into().unwrap());
        }

        let cfg = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(cfg);
        let mut input_targets = Vec::with_capacity(16);
        for _ in 0..16 {
            input_targets.push(builder.add_virtual_target());
        }
        let out = keccak256_u32_words_be_abi(&mut builder, &input_targets);
        for limb in out {
            builder.register_public_input(limb.0);
        }
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        for (t, v) in input_targets.iter().zip(limbs.iter()) {
            pw.set_target(*t, F::from_canonical_u64(*v as u64));
        }
        let proof = data.prove(pw).unwrap();
        let got: Vec<u32> = proof.public_inputs.iter().map(|x| x.to_canonical_u64() as u32).collect();
        assert_eq!(got, expected.to_vec());
    }

    #[test]
    fn tiny_keccak_alloy_and_circuit_match_for_two_u32_as_uint32_pair() {
        type F = GoldilocksField;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;

        let a: u32 = 0x11223344;
        let b: u32 = 0xa1b2c3d4;

        let packed = (a, b).abi_encode_packed();
        let expected = keccak_digest_bytes_to_u32x8(&packed);

        let cfg = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(cfg);
        let input_targets = vec![builder.add_virtual_target(), builder.add_virtual_target()];
        let out = keccak256_u32_words_be_abi(&mut builder, &input_targets);
        for limb in out {
            builder.register_public_input(limb.0);
        }
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_target(input_targets[0], F::from_canonical_u64(a as u64));
        pw.set_target(input_targets[1], F::from_canonical_u64(b as u64));
        let proof = data.prove(pw).unwrap();
        let got: Vec<u32> = proof.public_inputs.iter().map(|x| x.to_canonical_u64() as u32).collect();
        assert_eq!(got, expected.to_vec());
    }

    #[test]
    fn tiny_keccak_alloy_and_circuit_match_for_single_u32_as_uint32() {
        type F = GoldilocksField;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;

        let a: u32 = 0x11223344;

        let packed = a.abi_encode_packed();
        let expected = keccak_digest_bytes_to_u32x8(&packed);

        let cfg = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(cfg);
        let input_targets = vec![builder.add_virtual_target()];
        let out = keccak256_u32_words_be_abi(&mut builder, &input_targets);
        for limb in out {
            builder.register_public_input(limb.0);
        }
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_target(input_targets[0], F::from_canonical_u64(a as u64));
        let proof = data.prove(pw).unwrap();
        let got: Vec<u32> = proof.public_inputs.iter().map(|x| x.to_canonical_u64() as u32).collect();
        assert_eq!(got, expected.to_vec());
    }

    #[test]
    fn tiny_keccak_alloy_and_circuit_differs_from_two_u32_as_bytes4_le_pair() {
        type F = GoldilocksField;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;

        let a: u32 = 0x11223344;
        let b: u32 = 0xa1b2c3d4;

        let packed_bytes4_le = (FixedBytes::<4>::from(a.to_le_bytes()), FixedBytes::<4>::from(b.to_le_bytes())).abi_encode_packed();
        let expected_bytes4_le = keccak_digest_bytes_to_u32x8(&packed_bytes4_le);

        let cfg = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(cfg);
        let input_targets = vec![builder.add_virtual_target(), builder.add_virtual_target()];
        let out = keccak256_u32_words_be_abi(&mut builder, &input_targets);
        for limb in out {
            builder.register_public_input(limb.0);
        }
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_target(input_targets[0], F::from_canonical_u64(a as u64));
        pw.set_target(input_targets[1], F::from_canonical_u64(b as u64));
        let proof = data.prove(pw).unwrap();
        let got: Vec<u32> = proof.public_inputs.iter().map(|x| x.to_canonical_u64() as u32).collect();
        assert_ne!(got, expected_bytes4_le.to_vec());
    }

    #[test]
    fn single_keccak_u32x16_degree_bits_is_13() {
        type F = GoldilocksField;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;

        let cfg = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(cfg);
        let mut input_targets = Vec::with_capacity(16);
        for _ in 0..16 {
            input_targets.push(builder.add_virtual_target());
        }
        let out = keccak256_u32_words_be_abi(&mut builder, &input_targets);
        for limb in out {
            builder.register_public_input(limb.0);
        }

        let data = builder.build::<C>();
        assert_eq!(data.common.degree_bits(), 13);
        assert_eq!(data.common.degree(), 1 << 13);
    }
}
