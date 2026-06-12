#[cfg(test)]
mod tests {
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::crypto::{
        bn254::{
            curve::g2::G2,
            field::{bn128_base::Bn128Base, bn128_scalar::Bn128Scalar},
            gadgets::{g1::CircuitBuilderG1, nonnative_fp::CircuitBuilderNonNative, pairing::CircuitBuilderCurveG2},
            pairing_config,
        },
        kzg::{CircuitBuilderKZG, KZGCommitmentTarget, KZGProofTarget},
        secp256k1::ecdsa::curve::curve_types::Curve,
    };
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_kzg_full_flow() {
        let mut builder = CircuitBuilder::<F, D>::new(pairing_config());
        let val1 = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5));
        let val2 = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5));
        builder.connect_nonnative(&val1, &val2);

        let data = builder.build::<C>();

        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_kzg_batch_verify() {
        let mut builder = CircuitBuilder::<F, D>::new(pairing_config());

        let g1_gen = builder.g1_generator();
        let commitment1 = KZGCommitmentTarget { commitment: g1_gen.clone() };
        let commitment2 = KZGCommitmentTarget { commitment: g1_gen.clone() };

        let point1 = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(1));
        let point2 = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2));
        let eval1 = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(1));
        let eval2 = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2));

        let proof1 = KZGProofTarget { w: g1_gen.clone() };
        let proof2 = KZGProofTarget { w: g1_gen.clone() };

        let g2_tau = builder.constant_affine_point_g2::<G2, Bn128Base>(G2::GENERATOR_AFFINE);

        let _is_valid = builder.kzg_batch_verify(
            &[commitment1, commitment2],
            &[point1, point2],
            &[eval1, eval2],
            &[proof1, proof2],
            &g2_tau,
        );

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }
}
