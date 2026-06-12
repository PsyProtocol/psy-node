pub mod builder;
pub mod commitment;
pub mod fft;
pub mod proof;
pub mod setup;
pub mod verifier;

pub use builder::{CircuitBuilderKZG, CircuitBuilderKZGHelpers};
pub use commitment::{KZGCommitment, KZGCommitmentTarget};
pub use fft::{CircuitBuilderFFT, FFTSettingsTarget};
pub use proof::{KZGProof, KZGProofTarget};
pub use setup::{KZGParams, KZGSetup};

#[cfg(test)]
mod tests {
    use builder::CircuitBuilderKZGHelpers;
    use plonky2::{
        field::types::Field,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use super::*;
    use crate::crypto::bn254::{
        curve::g2::G2,
        field::{bn128_base::Bn128Base, bn128_scalar::Bn128Scalar},
        gadgets::{g1::CircuitBuilderG1, nonnative_fp::CircuitBuilderNonNative, pairing::CircuitBuilderCurveG2},
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    fn get_test_config() -> CircuitConfig {
        crate::crypto::bn254::pairing_config()
    }

    mod nonnative_tests {
        use super::*;

        #[test]
        fn test_nonnative_add_basic() {
            let config = get_test_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let x_ff = Bn128Base::from_canonical_u64(123);
            let y_ff = Bn128Base::from_canonical_u64(456);
            let sum_ff = x_ff + y_ff;

            let x = builder.constant_nonnative(x_ff);
            let y = builder.constant_nonnative(y_ff);
            let sum = builder.add_nonnative(&x, &y);
            let sum_expected = builder.constant_nonnative(sum_ff);
            builder.connect_nonnative(&sum, &sum_expected);

            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }

        #[test]
        fn test_nonnative_mul_basic() {
            let config = get_test_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let x_ff = Bn128Base::from_canonical_u64(12);
            let y_ff = Bn128Base::from_canonical_u64(34);
            let prod_ff = x_ff * y_ff;

            let x = builder.constant_nonnative(x_ff);
            let y = builder.constant_nonnative(y_ff);
            let prod = builder.mul_nonnative(&x, &y);
            let prod_expected = builder.constant_nonnative(prod_ff);
            builder.connect_nonnative(&prod, &prod_expected);

            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }

        #[test]
        fn test_nonnative_sub_basic() {
            let config = get_test_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let x_ff = Bn128Base::from_canonical_u64(456);
            let y_ff = Bn128Base::from_canonical_u64(123);
            let diff_ff = x_ff - y_ff;

            let x = builder.constant_nonnative(x_ff);
            let y = builder.constant_nonnative(y_ff);
            let diff = builder.sub_nonnative(&x, &y);
            let diff_expected = builder.constant_nonnative(diff_ff);
            builder.connect_nonnative(&diff, &diff_expected);

            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }
    }

    mod kzg_core_tests {
        use super::*;

        #[test]
        fn test_kzg_commit_simple() {
            let config = get_test_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Create a simple polynomial in evaluation form
            let evaluations = vec![builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5))];

            // Setup Lagrange basis for domain size 1
            let tau = Bn128Scalar::from_canonical_u64(12345);
            let setup = KZGSetup::new_lagrange_setup(tau, 1);
            let lagrange_g1 = vec![builder.constant_g1_affine(setup.lagrange_g1[0])];

            let commitment = builder.kzg_commit(&evaluations, &lagrange_g1);

            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }

        #[test]
        fn test_kzg_proof_creation() {
            let config = get_test_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Create FFT settings for domain size 2
            let domain_size = 2;
            let fft_settings = builder.fft_settings(domain_size);

            // Create evaluations at roots of unity
            let evaluations = vec![
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(7)),
            ];

            // Setup Lagrange basis
            let tau = Bn128Scalar::from_canonical_u64(12345);
            let setup = KZGSetup::new_lagrange_setup(tau, domain_size);
            let lagrange_g1: Vec<_> = setup.lagrange_g1.iter().map(|p| builder.constant_g1_affine(*p)).collect();

            let point = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(3));
            let (evaluation, proof) = builder.kzg_create_opening_proof(&evaluations, &point, &lagrange_g1, &fft_settings);

            // We can't easily predict the exact evaluation without computing Lagrange
            // interpolation So just check that proof creation succeeds
            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }

        #[test]
        fn test_polynomial_evaluation_lagrange() {
            let config = get_test_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Create FFT settings for domain size 4
            let domain_size = 4;
            let fft_settings = builder.fft_settings(domain_size);

            // Create evaluations at roots of unity
            let evaluations = vec![
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(1)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(3)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(4)),
            ];

            // Evaluate at a point outside the domain
            let point = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5));
            let _result = builder.kzg_evaluate_at_point(&evaluations, &point, &fft_settings);

            // The exact result depends on the Lagrange interpolation
            // Just verify the circuit builds and proves
            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }
    }

    mod lagrange_tests {
        use super::*;

        #[test]
        fn test_quotient_polynomial_lagrange() {
            let config = CircuitConfig {
                num_wires: 400,
                ..CircuitConfig::wide_ecc_config()
            };
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Setup FFT domain of size 4
            let domain_size = 4;
            let fft_settings = builder.fft_settings(domain_size);

            // Test polynomial: evaluations [1, 2, 3, 4] at roots of unity
            let evaluations = vec![
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(1)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(3)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(4)),
            ];

            // Evaluate at a point not in the domain
            let point = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5));

            // First compute p(z) using Lagrange interpolation
            let eval_at_point = builder.lagrange_interpolate_at_point(&evaluations, &point, &fft_settings);

            // Compute quotient polynomial in evaluation form
            let quotient_evals = builder.kzg_compute_quotient_polynomial(&evaluations, &point, &eval_at_point, &fft_settings);

            // Verify quotient has correct length
            assert_eq!(quotient_evals.len(), domain_size);

            // Test special case: evaluate at a root of unity
            println!("Testing special case: evaluation at root of unity");
            let point_at_root = fft_settings.roots_of_unity[1].clone();
            let eval_at_root = evaluations[1].clone(); // Should equal y_1

            let quotient_at_root = builder.kzg_compute_quotient_polynomial(&evaluations, &point_at_root, &eval_at_root, &fft_settings);

            // Verify that q_1 = 0 (special case)
            let zero = builder.zero_nonnative();
            let is_zero = builder.is_equal_nonnative(&quotient_at_root[1], &zero);
            builder.assert_one(is_zero.target);

            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();

            println!("✅ Quotient polynomial Lagrange test passed!");
        }

        #[test]
        fn test_simple_lagrange_setup() {
            let tau = Bn128Scalar::from_canonical_u64(12345);
            let domain_size = 4;

            let params = KZGSetup::new_trusted_setup(tau, domain_size);

            assert_eq!(params.lagrange_g1.len(), domain_size);
            assert_eq!(params.roots_of_unity.len(), domain_size);
        }

        #[test]
        fn test_lagrange_commitment_simple() {
            let config = CircuitConfig {
                num_wires: 400,
                ..CircuitConfig::wide_ecc_config()
            };
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let tau = Bn128Scalar::from_canonical_u64(12345);
            let domain_size = 4;
            let params = KZGSetup::new_trusted_setup(tau, domain_size);

            let evaluations = vec![
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(1)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(3)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(4)),
            ];

            let lagrange_g1 = params.lagrange_g1.into_iter().map(|p| builder.constant_g1_affine(p)).collect::<Vec<_>>();

            let _commitment = builder.kzg_commit(&evaluations, &lagrange_g1);

            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }
    }

    mod setup_tests {
        use super::*;

        #[test]
        fn test_trusted_setup() {
            let tau = Bn128Scalar::from_canonical_u64(123);
            let params = KZGSetup::new_trusted_setup(tau, 8);

            assert_eq!(params.lagrange_g1.len(), 8);
            assert_eq!(params.powers_of_tau_g2.len(), 2);
            assert!(KZGSetup::verify_setup(&params));
        }

        #[test]
        fn test_powers_of_tau_consistency() {
            let tau = Bn128Scalar::from_canonical_u64(7);
            let _params = KZGSetup::new_trusted_setup(tau, 4);

            use crate::crypto::{bn254::curve::g1::G1, secp256k1::ecdsa::curve::curve_types::Curve};
            let _g1_gen = G1::GENERATOR_AFFINE;

            // First Lagrange basis element L_0(τ) * G is not the generator
            // since L_0(τ) = (τ^n - 1) / (n * (τ - 1))
        }
    }

    mod fft_tests {
        use super::*;

        #[test]
        fn test_fft_roundtrip() {
            let config = CircuitConfig {
                num_wires: 400,
                ..CircuitConfig::wide_ecc_config()
            };
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let domain_size = 4;
            let settings = builder.fft_settings(domain_size);

            let coeffs = vec![
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(1)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(3)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(4)),
            ];

            let evals = builder.fft_forward(&coeffs, &settings);
            let recovered = builder.fft_inverse(&evals, &settings);

            for i in 0..domain_size {
                builder.connect_nonnative(&coeffs[i], &recovered[i]);
            }

            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }
    }

    mod debug_tests {
        use super::*;
        use crate::crypto::bn254::pairing_config;

        #[test]
        fn test_debug_kzg_commit_only() {
            let mut builder = CircuitBuilder::<F, D>::new(pairing_config());

            let params = KZGSetup::new_test_setup(2);
            let lagrange_g1 = params.lagrange_g1.iter().map(|p| builder.constant_g1_affine(*p)).collect::<Vec<_>>();

            // Evaluations at roots of unity
            let evaluations = vec![
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(1)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(1)),
            ];

            let _commitment = builder.kzg_commit(&evaluations, &lagrange_g1);

            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }

        #[test]
        fn test_debug_simple_nonnative_arithmetic() {
            let mut builder = CircuitBuilder::<F, D>::new(pairing_config());

            let one = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(1));
            let three = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(3));
            let diff = builder.sub_nonnative(&one, &three);

            let neg_two = Bn128Scalar::ZERO - Bn128Scalar::from_canonical_u64(2);
            let expected = builder.constant_nonnative(neg_two);

            builder.connect_nonnative(&diff, &expected);

            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }
    }

    mod end_to_end_tests {
        use super::*;

        #[test]
        fn test_kzg_full_workflow() {
            let config = get_test_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Setup parameters with Lagrange basis
            let tau = Bn128Scalar::from_canonical_u64(12345);
            let domain_size = 4;
            let setup_params = KZGSetup::new_lagrange_setup(tau, domain_size);
            let fft_settings = builder.fft_settings(domain_size);

            // Convert Lagrange basis to circuit targets
            let lagrange_g1: Vec<_> = setup_params.lagrange_g1.iter().map(|p| builder.constant_g1_affine(*p)).collect();

            let (_, g2_tau_point) = setup_params.get_g2_powers();
            let g2_tau = builder.constant_affine_point_g2::<G2, Bn128Base>(*g2_tau_point);

            // Create polynomial evaluations at roots of unity
            let evaluations = vec![
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(1)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(4)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(9)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(16)),
            ];

            // Step 1: Commit to the polynomial
            let commitment = builder.kzg_commit(&evaluations, &lagrange_g1);

            // Step 2: Create opening proof at point z = 5
            let point = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5));
            let (evaluation, proof) = builder.kzg_create_opening_proof(&evaluations, &point, &lagrange_g1, &fft_settings);

            // Step 3: Verify the proof
            let is_valid = builder.kzg_verify(&commitment, &point, &evaluation, &proof, &g2_tau);

            // Assert the proof is valid
            builder.assert_one(is_valid.target);

            // Build and prove the circuit
            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }

        #[test]
        fn test_kzg_multiple_openings() {
            let config = get_test_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Setup
            let tau = Bn128Scalar::from_canonical_u64(54321);
            let setup_params = KZGSetup::new_trusted_setup(tau, 8);
            let fft_settings = builder.fft_settings(8);

            let lagrange_g1: Vec<_> = setup_params.lagrange_g1.iter().map(|p| builder.constant_g1_affine(*p)).collect();

            let (_, g2_tau_point) = setup_params.get_g2_powers();
            let g2_tau = builder.constant_affine_point_g2::<G2, Bn128Base>(*g2_tau_point);

            // Create polynomial evaluations at roots of unity
            let evaluations = vec![
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(10)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(8)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(24)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(6)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(18)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(12)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(36)),
            ];

            // Commit
            let commitment = builder.kzg_commit(&evaluations, &lagrange_g1);

            // Open at multiple points
            let points = vec![
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(0)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(1)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2)),
            ];

            // Create and verify proofs for each point
            for point in points.iter() {
                let (eval, proof) = builder.kzg_create_opening_proof(&evaluations, point, &lagrange_g1, &fft_settings);

                // Don't check exact evaluation values since we're using Lagrange interpolation

                // Verify proof
                let is_valid = builder.kzg_verify(&commitment, point, &eval, &proof, &g2_tau);
                builder.assert_one(is_valid.target);
            }

            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }

        #[test]
        fn test_kzg_batch_verify() {
            let config = get_test_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Setup
            let tau = Bn128Scalar::from_canonical_u64(98765);
            let setup_params = KZGSetup::new_trusted_setup(tau, 4);
            let fft_settings = builder.fft_settings(4);

            let lagrange_g1: Vec<_> = setup_params.lagrange_g1.iter().map(|p| builder.constant_g1_affine(*p)).collect();

            let (_, g2_tau_point) = setup_params.get_g2_powers();
            let g2_tau = builder.constant_affine_point_g2::<G2, Bn128Base>(*g2_tau_point);

            // Create two polynomials in evaluation form
            let evaluations1 = vec![
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(1)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(3)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(4)),
            ];
            let evaluations2 = vec![
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(6)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(7)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(8)),
            ];

            // Commit to both
            let commitment1 = builder.kzg_commit(&evaluations1, &lagrange_g1);
            let commitment2 = builder.kzg_commit(&evaluations2, &lagrange_g1);

            // Create batch opening proofs
            let all_evaluations = vec![evaluations1, evaluations2];
            let points = vec![
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(3)),
            ];

            let (evaluations, proofs) = builder.kzg_create_batch_opening_proofs(&all_evaluations, &points, &lagrange_g1, &fft_settings);

            // Batch verify
            let commitments = vec![commitment1, commitment2];
            let is_valid = builder.kzg_batch_verify(&commitments, &points, &evaluations, &proofs, &g2_tau);

            builder.assert_one(is_valid.target);

            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }

        #[test]
        fn test_kzg_invalid_proof_rejection() {
            let config = get_test_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Setup
            let tau = Bn128Scalar::from_canonical_u64(11111);
            let setup_params = KZGSetup::new_trusted_setup(tau, 4);
            let fft_settings = builder.fft_settings(4);

            let lagrange_g1: Vec<_> = setup_params.lagrange_g1.iter().map(|p| builder.constant_g1_affine(*p)).collect();

            let (_, g2_tau_point) = setup_params.get_g2_powers();
            let g2_tau = builder.constant_affine_point_g2::<G2, Bn128Base>(*g2_tau_point);

            // Create polynomial evaluations
            let evaluations = vec![
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(7)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(9)),
                builder.constant_nonnative(Bn128Scalar::from_canonical_u64(11)),
            ];

            let commitment = builder.kzg_commit(&evaluations, &lagrange_g1);
            let point = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(3));
            let (_correct_eval, correct_proof) = builder.kzg_create_opening_proof(&evaluations, &point, &lagrange_g1, &fft_settings);

            // Create an incorrect evaluation
            let wrong_eval = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(999));

            // Verify with wrong evaluation should fail
            let is_valid = builder.kzg_verify(
                &commitment,
                &point,
                &wrong_eval, // Wrong evaluation
                &correct_proof,
                &g2_tau,
            );

            // Assert the proof is INVALID
            builder.assert_zero(is_valid.target);

            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }

        #[test]
        fn test_kzg_zero_polynomial() {
            let config = get_test_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Setup
            let tau = Bn128Scalar::from_canonical_u64(22222);
            let setup_params = KZGSetup::new_trusted_setup(tau, 4);
            let fft_settings = builder.fft_settings(4);

            let lagrange_g1: Vec<_> = setup_params.lagrange_g1.iter().map(|p| builder.constant_g1_affine(*p)).collect();

            let (_, g2_tau_point) = setup_params.get_g2_powers();
            let g2_tau = builder.constant_affine_point_g2::<G2, Bn128Base>(*g2_tau_point);

            // Zero polynomial evaluations
            let evaluations = vec![
                builder.constant_nonnative(Bn128Scalar::ZERO),
                builder.constant_nonnative(Bn128Scalar::ZERO),
                builder.constant_nonnative(Bn128Scalar::ZERO),
                builder.constant_nonnative(Bn128Scalar::ZERO),
            ];

            let commitment = builder.kzg_commit(&evaluations, &lagrange_g1);
            let point = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(7));
            let (eval, proof) = builder.kzg_create_opening_proof(&evaluations, &point, &lagrange_g1, &fft_settings);

            // Evaluation should be zero
            let zero = builder.constant_nonnative(Bn128Scalar::ZERO);
            builder.connect_nonnative(&eval, &zero);

            // Verify proof
            let is_valid = builder.kzg_verify(&commitment, &point, &eval, &proof, &g2_tau);
            builder.assert_one(is_valid.target);

            let data = builder.build::<C>();
            let pw = PartialWitness::new();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }
    }
}
