// regression: an all-ones u32 word must hash correctly in-circuit (the
// theta fold used to mis-evaluate via unsafe_xor_many_u64).
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    field::types::{Field, PrimeField64},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
};
use psy_plonky2_common_circuits::hash::keccak::keccak256_u32_words_be_abi;
use tiny_keccak::{Hasher as _, Keccak};

fn native_keccak(words: &[u64]) -> Vec<u64> {
    let mut bytes = Vec::new();
    for w in words {
        bytes.extend_from_slice(&(*w as u32).to_be_bytes());
    }
    let mut digest = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(&bytes);
    k.finalize(&mut digest);
    digest.chunks_exact(4).take(8).map(|c| u32::from_be_bytes(c.try_into().unwrap()) as u64).collect()
}

#[test]
fn keccak_all_ones_words_match_native() {
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    let cases: [&[u64]; 4] = [
        &[0xffff_ffff],
        &[0xffff_ffff, 0],
        &[0, 0xffff_ffff],
        &[0xffff_ffff, 0xffff_ffff, 0xffff_ffff],
    ];
    for words in cases {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let targets: Vec<_> = (0..words.len()).map(|_| builder.add_virtual_target()).collect();
        let out = keccak256_u32_words_be_abi(&mut builder, &targets);
        for o in out {
            builder.register_public_input(o.0);
        }
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        for (t, w) in targets.iter().zip(words) {
            pw.set_target(*t, F::from_noncanonical_u64(*w)).unwrap();
        }
        let proof = data.prove(pw).expect("all-ones words must prove");
        data.verify(proof.clone()).expect("proof must verify");
        let got: Vec<u64> = proof.public_inputs.iter().map(|f| f.to_canonical_u64()).collect();
        let native = native_keccak(words);
        assert_eq!(got, native, "keccak mismatch for words {words:#010x?}");
    }
}
