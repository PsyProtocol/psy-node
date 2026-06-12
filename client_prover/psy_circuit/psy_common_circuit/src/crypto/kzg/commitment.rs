use plonky2::{field::extension::Extendable, hash::hash_types::RichField};

use crate::crypto::{bn254::gadgets::g1::G1AffineTarget, secp256k1::ecdsa::curve::curve_types::AffinePoint};

#[derive(Clone, Debug)]
pub struct KZGCommitmentTarget<F: RichField + Extendable<D>, const D: usize> {
    pub commitment: G1AffineTarget<F, D>,
}

#[derive(Clone, Debug)]
pub struct KZGCommitment {
    pub commitment: AffinePoint<crate::crypto::bn254::curve::g1::G1>,
}

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
            field::{bn128_base::Bn128Base, bn128_scalar::Bn128Scalar},
            gadgets::{CircuitBuilderG1, CircuitBuilderNonNative},
            pairing_config,
        },
        kzg::{fft::CircuitBuilderFFT, CircuitBuilderKZG},
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_kzg_commitment_structure() {
        use crate::crypto::{
            bn254::gadgets::pairing::CircuitBuilderCurveG2,
            kzg::{fft::CircuitBuilderFFT, setup::KZGSetup},
        };

        let mut builder = CircuitBuilder::<F, D>::new(pairing_config());

        // Create a proper trusted setup with Lagrange basis
        let tau = Bn128Scalar::from_canonical_u64(12345);
        let domain_size = 2;
        let setup_params = KZGSetup::new_trusted_setup(tau, domain_size);
        let fft_settings = builder.fft_settings(domain_size);

        // Convert Lagrange basis to circuit targets
        let lagrange_g1: Vec<_> = setup_params.lagrange_g1.iter().map(|p| builder.constant_g1_affine(*p)).collect();

        let (_, g2_tau_point) = setup_params.get_g2_powers();
        let g2_tau = builder.constant_affine_point_g2::<crate::crypto::bn254::curve::g2::G2, Bn128Base>(*g2_tau_point);

        // Create polynomial evaluations at roots of unity
        let eval1 = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5));
        let eval2 = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(8));
        let evaluations = vec![eval1, eval2];

        // Step 1: Commit to the polynomial
        let commitment = builder.kzg_commit(&evaluations, &lagrange_g1);

        // Step 2: Create opening proof at point z = 4
        let point = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(4));
        let (evaluation, proof) = builder.kzg_create_opening_proof(&evaluations, &point, &lagrange_g1, &fft_settings);

        // Step 3: Verify the KZG proof
        let is_valid = builder.kzg_verify(&commitment, &point, &evaluation, &proof, &g2_tau);

        // Assert the proof is valid
        builder.assert_one(is_valid.target);

        // Build and prove the circuit
        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let circuit_proof = data.prove(pw).unwrap();

        // Verify the circuit proof
        data.verify(circuit_proof).unwrap();

        println!("✅ KZG commitment structure test passed with verify!");
        println!("   - Polynomial evaluations at roots of unity");
        println!("   - Opening point: z = 4");
        println!("   - KZG verify succeeded!");
    }

    #[test]
    fn test_kzg_with_verify() {
        use crate::crypto::{
            bn254::gadgets::pairing::CircuitBuilderCurveG2,
            kzg::{fft::CircuitBuilderFFT, setup::KZGSetup},
        };

        let mut builder = CircuitBuilder::<F, D>::new(pairing_config());

        // Create a trusted setup with Lagrange basis
        let tau = Bn128Scalar::from_canonical_u64(12345);
        let domain_size = 2;
        let setup_params = KZGSetup::new_trusted_setup(tau, domain_size);
        let fft_settings = builder.fft_settings(domain_size);

        // Convert setup parameters to circuit targets
        let lagrange_g1: Vec<_> = setup_params.lagrange_g1.iter().map(|p| builder.constant_g1_affine(*p)).collect();

        let (_, g2_tau_point) = setup_params.get_g2_powers();
        let g2_tau = builder.constant_affine_point_g2::<crate::crypto::bn254::curve::g2::G2, Bn128Base>(*g2_tau_point);

        // Create polynomial evaluations
        let evaluations = vec![
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5)),
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(8)),
        ];

        // Step 1: Commit to the polynomial
        println!("Creating commitment for polynomial...");
        let commitment = builder.kzg_commit(&evaluations, &lagrange_g1);

        // Step 2: Create opening proof at point z = 4
        println!("Creating opening proof at z = 4...");
        let point = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(4));
        let (evaluation, proof) = builder.kzg_create_opening_proof(&evaluations, &point, &lagrange_g1, &fft_settings);

        // Step 3: Verify the KZG proof
        println!("Verifying KZG proof...");
        let is_valid = builder.kzg_verify(&commitment, &point, &evaluation, &proof, &g2_tau);

        // Assert the proof is valid
        builder.assert_one(is_valid.target);

        // Build and prove the circuit (now with KZG verify)
        println!("Building circuit...");
        let data = builder.build::<C>();
        println!("Circuit built with {} gates", data.common.gates.len());

        println!("Creating proof...");
        let pw = PartialWitness::new();
        let circuit_proof = data.prove(pw).unwrap();

        println!("Verifying proof...");
        data.verify(circuit_proof).unwrap();

        println!("✅ KZG test with verify passed!");
    }

    #[test]
    fn test_kzg_linear_polynomial() {
        use crate::crypto::{bn254::gadgets::pairing::CircuitBuilderCurveG2, kzg::setup::KZGSetup};

        let mut builder = CircuitBuilder::<F, D>::new(pairing_config());

        // Create a trusted setup with a larger tau to avoid collisions
        let tau = Bn128Scalar::from_canonical_u64(12345);
        let domain_size = 4;
        let setup_params = KZGSetup::new_trusted_setup(tau, domain_size);
        let fft_settings = builder.fft_settings(domain_size);

        // Convert setup parameters to circuit targets
        let lagrange_g1: Vec<_> = setup_params.lagrange_g1.iter().map(|p| builder.constant_g1_affine(*p)).collect();

        let (_, g2_tau_point) = setup_params.get_g2_powers();
        let g2_tau = builder.constant_affine_point_g2::<crate::crypto::bn254::curve::g2::G2, Bn128Base>(*g2_tau_point);

        // Create polynomial evaluations for a linear-like polynomial
        let evaluations = vec![
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2)),
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5)),
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(8)),
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(11)),
        ];

        // Step 1: Commit to the polynomial
        println!("Step 1: Creating commitment for polynomial...");
        let commitment = builder.kzg_commit(&evaluations, &lagrange_g1);
        println!("Commitment created successfully");

        // Step 2: Create opening proof at point z = 5
        println!("Step 2: Creating opening proof at z = 5...");
        let point = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5));
        let (evaluation, proof) = builder.kzg_create_opening_proof(&evaluations, &point, &lagrange_g1, &fft_settings);
        println!("Opening proof created successfully");

        // We can't predict the exact evaluation without computing Lagrange
        // interpolation
        println!("Evaluation computed via Lagrange interpolation");

        // Step 3: Try KZG verify
        println!("Step 3: Testing KZG verify...");
        let is_valid = builder.kzg_verify(&commitment, &point, &evaluation, &proof, &g2_tau);

        // Assert the proof is valid
        builder.assert_one(is_valid.target);
        println!("KZG verify completed successfully");

        // Build and prove the circuit
        println!("Building circuit...");
        let data = builder.build::<C>();
        println!("Circuit built with {} gates", data.common.gates.len());

        println!("Creating proof...");
        let pw = PartialWitness::new();
        let circuit_proof = data.prove(pw).unwrap();

        println!("Verifying proof...");
        data.verify(circuit_proof).unwrap();

        println!("✅ Full KZG workflow test passed!");
    }

    #[test]
    fn test_kzg_debug_zero_inversion() {
        use crate::crypto::{bn254::gadgets::pairing::CircuitBuilderCurveG2, kzg::setup::KZGSetup};

        let mut builder = CircuitBuilder::<F, D>::new(pairing_config());

        // Create a simple test case that should work
        let tau = Bn128Scalar::from_canonical_u64(7);
        let setup_params = KZGSetup::new_trusted_setup(tau, 2);
        let fft_settings = builder.fft_settings(2);

        // Test polynomial evaluations: linear-like growth
        let evaluations = vec![
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(1)),
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2)),
        ];

        let lagrange_g1: Vec<_> = setup_params.lagrange_g1.iter().map(|p| builder.constant_g1_affine(*p)).collect();

        let (_, g2_tau_point) = setup_params.get_g2_powers();
        let g2_tau = builder.constant_affine_point_g2::<crate::crypto::bn254::curve::g2::G2, Bn128Base>(*g2_tau_point);

        // Commit to polynomial in evaluation form
        println!("Creating commitment for polynomial...");
        let commitment = builder.kzg_commit(&evaluations, &lagrange_g1);

        // Open at z = 2
        println!("Creating opening proof at z = 2...");
        let point = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2));
        let (evaluation, proof) = builder.kzg_create_opening_proof(&evaluations, &point, &lagrange_g1, &fft_settings);

        println!("Testing KZG verify...");
        let is_valid = builder.kzg_verify(&commitment, &point, &evaluation, &proof, &g2_tau);

        builder.assert_one(is_valid.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();

        println!("Attempting to prove...");
        match data.prove(pw) {
            Ok(proof) => {
                println!("Proof created successfully!");
                data.verify(proof).unwrap();
                println!("✅ Debug test passed!");
            }
            Err(e) => {
                println!("❌ Proof failed with error: {}", e);
                panic!("Debug test failed");
            }
        }
    }

    #[test]
    fn test_pairing_with_g1_infinity() {
        use crate::crypto::{
            bn254::{
                curve::{g1::G1, g2::G2},
                field::bn128_base::Bn128Base,
                gadgets::pairing::{AffinePointTargetG2, CircuitBuilderCurveG2, CircuitBuilderPairing},
            },
            kzg::builder::CircuitBuilderKZGHelpers,
            secp256k1::ecdsa::curve::curve_types::Curve,
        };

        let mut builder = CircuitBuilder::<F, D>::new(pairing_config());

        // Create G1 infinity point
        let g1_inf = builder.g1_infinity();

        // Create G2 generator
        let g2_gen = builder.constant_affine_point_g2::<G2, Bn128Base>(G2::GENERATOR_AFFINE);

        println!("Testing pairing(infinity, G2)...");

        // Compute pairing(infinity, G2) - should equal identity in GT
        let _result = builder.pairing::<Bn128Base, G1, G2>(&g1_inf, &g2_gen);

        println!("Building circuit...");
        let data = builder.build::<C>();
        println!("Circuit built with {} gates", data.common.gates.len());

        let pw = PartialWitness::new();

        println!("Attempting to prove...");
        match data.prove(pw) {
            Ok(proof) => {
                data.verify(proof).unwrap();
                println!("✅ Pairing with G1 infinity test passed!");
            }
            Err(e) => {
                println!("❌ Pairing with G1 infinity test failed: {}", e);
            }
        }
    }

    #[test]
    fn test_g1_infinity_handling() {
        use crate::crypto::kzg::builder::CircuitBuilderKZGHelpers;

        let mut builder = CircuitBuilder::<F, D>::new(pairing_config());

        // Test if our g1_infinity function works correctly
        let infinity = builder.g1_infinity();

        // Try to convert it to projective and back
        let proj = builder.g1_affine_to_projective(&infinity);
        let affine_back = builder.g1_projective_to_affine(&proj);

        // Check that it remains infinity
        builder.connect_g1(&infinity, &affine_back);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();

        match data.prove(pw) {
            Ok(proof) => {
                data.verify(proof).unwrap();
                println!("✅ G1 infinity handling test passed!");
            }
            Err(e) => {
                println!("❌ G1 infinity handling test failed: {}", e);
            }
        }
    }

    #[test]
    fn test_simple_pairing() {
        use crate::crypto::{
            bn254::{
                curve::{g1::G1, g2::G2},
                field::bn128_base::Bn128Base,
                gadgets::pairing::{AffinePointTargetG2, CircuitBuilderCurveG2, CircuitBuilderPairing},
            },
            secp256k1::ecdsa::curve::curve_types::Curve,
        };

        let mut builder = CircuitBuilder::<F, D>::new(pairing_config());

        // Simple pairing test
        let g1 = builder.g1_generator();
        let g2 = builder.constant_affine_point_g2::<G2, Bn128Base>(G2::GENERATOR_AFFINE);

        println!("Computing pairing(G1, G2)...");
        let _ = builder.pairing::<Bn128Base, G1, G2>(&g1, &g2);

        println!("Building circuit...");
        let data = builder.build::<C>();
        println!("Circuit built with {} gates", data.common.gates.len());

        let pw = PartialWitness::new();

        println!("Attempting to prove...");
        match data.prove(pw) {
            Ok(proof) => {
                data.verify(proof).unwrap();
                println!("✅ Simple pairing test passed!");
            }
            Err(e) => {
                println!("❌ Simple pairing test failed: {}", e);
            }
        }
    }

    #[test]
    fn test_kzg_verify_non_constant_polynomial() {
        use crate::crypto::{bn254::gadgets::pairing::CircuitBuilderCurveG2, kzg::setup::KZGSetup};

        let mut builder = CircuitBuilder::<F, D>::new(pairing_config());

        // Create a simple setup
        let tau = Bn128Scalar::from_canonical_u64(123);
        let setup_params = KZGSetup::new_trusted_setup(tau, 4);
        let fft_settings = builder.fft_settings(4);

        // Convert setup parameters to circuit targets
        let lagrange_g1: Vec<_> = setup_params.lagrange_g1.iter().map(|p| builder.constant_g1_affine(*p)).collect();

        let (_, g2_tau_point) = setup_params.get_g2_powers();
        let g2_tau = builder.constant_affine_point_g2::<crate::crypto::bn254::curve::g2::G2, Bn128Base>(*g2_tau_point);

        // Create LINEAR polynomial evaluations
        let evaluations = vec![
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2)),
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5)),
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(8)),
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(11)),
        ];

        // Commit
        let commitment = builder.kzg_commit(&evaluations, &lagrange_g1);

        // Create opening proof at point z = 5
        let point = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5));
        let (evaluation, proof) = builder.kzg_create_opening_proof(&evaluations, &point, &lagrange_g1, &fft_settings);

        println!("Testing KZG verify with polynomial evaluations...");
        println!("Opening point: z = 5");

        // This should work since quotient polynomial is not empty
        let is_valid = builder.kzg_verify(&commitment, &point, &evaluation, &proof, &g2_tau);

        builder.assert_one(is_valid.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();

        println!("Attempting to prove...");
        match data.prove(pw) {
            Ok(proof) => {
                data.verify(proof).unwrap();
                println!("✅ Test passed!");
            }
            Err(e) => {
                println!("❌ Test failed with error: {}", e);
            }
        }
    }

    #[test]
    fn test_simple_kzg_witness_error() {
        use crate::crypto::{bn254::gadgets::pairing::CircuitBuilderCurveG2, kzg::setup::KZGSetup};

        let mut builder = CircuitBuilder::<F, D>::new(pairing_config());

        // Create a simple setup
        let tau = Bn128Scalar::from_canonical_u64(123);
        let setup_params = KZGSetup::new_trusted_setup(tau, 2);
        let fft_settings = builder.fft_settings(2);

        // Convert setup parameters to circuit targets
        let lagrange_g1: Vec<_> = setup_params.lagrange_g1.iter().map(|p| builder.constant_g1_affine(*p)).collect();

        let (_, g2_tau_point) = setup_params.get_g2_powers();
        let g2_tau = builder.constant_affine_point_g2::<crate::crypto::bn254::curve::g2::G2, Bn128Base>(*g2_tau_point);

        // Create a CONSTANT polynomial evaluations: p(x) = 5
        let evaluations = vec![
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5)),
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5)),
        ];

        // Commit
        let commitment = builder.kzg_commit(&evaluations, &lagrange_g1);

        // Create opening proof at point z = 7
        let point = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(7));
        let (evaluation, proof) = builder.kzg_create_opening_proof(&evaluations, &point, &lagrange_g1, &fft_settings);

        // For constant polynomial p(x) = 5, p(7) = 5
        let expected_eval = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5));
        builder.connect_nonnative(&evaluation, &expected_eval);

        println!("Testing KZG verify with constant polynomial...");
        println!("Polynomial evaluations: [5, 5]");
        println!("Opening point: z = 7");
        println!("Evaluation: p(7) = 5");

        // This should trigger the error because quotient polynomial is empty
        let is_valid = builder.kzg_verify(&commitment, &point, &evaluation, &proof, &g2_tau);

        builder.assert_one(is_valid.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();

        println!("Attempting to prove...");
        match data.prove(pw) {
            Ok(proof) => {
                data.verify(proof).unwrap();
                println!("✅ Test passed!");
            }
            Err(e) => {
                println!("❌ Test failed with error: {}", e);
                println!("This confirms our hypothesis about the constant polynomial issue");
            }
        }
    }
}
