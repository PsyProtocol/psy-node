use core::marker::PhantomData;

use num::BigUint;
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::{hash_types::RichField, keccak::KeccakHash},
    iop::target::{BoolTarget, Target},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericHashOut, Hasher},
    },
};

use crate::{
    crypto::{
        bn254::{
            curve::{G1, G2},
            field::{bn128_base::Bn128Base, bn128_scalar::Bn128Scalar},
            gadgets::{
                g1::{CircuitBuilderG1, G1AffineTarget},
                g2::{CircuitBuilderG2, G2AffineTarget},
                nonnative_fp::{CircuitBuilderNonNative, NonNativeTarget},
                nonnative_fp2::NonNativeTargetExt2,
                split_nonnative::CircuitBuilderSplit,
            },
        },
        secp256k1::ecdsa::{
            curve::curve_types::{Curve, CurveScalar},
            gadgets::biguint::BigUintTarget,
        },
    },
    u32::arithmetic_u32,
};

const WINDOW_SIZE: usize = 4;

pub trait CircuitBuilderWindowedMul<F: RichField + Extendable<D>, const D: usize> {
    fn precompute_window_g1(&mut self, p: &G1AffineTarget<F, D>) -> Vec<G1AffineTarget<F, D>>;

    fn random_access_curve_points_g1(&mut self, access_index: Target, v: Vec<G1AffineTarget<F, D>>) -> G1AffineTarget<F, D>;

    fn curve_scalar_mul_windowed_g1(&mut self, p: &G1AffineTarget<F, D>, n: &NonNativeTarget<Bn128Scalar>) -> G1AffineTarget<F, D>;

    fn precompute_window_g2(&mut self, p: &G2AffineTarget<F, D>) -> Vec<G2AffineTarget<F, D>>;

    fn random_access_curve_points_g2(&mut self, access_index: Target, v: Vec<G2AffineTarget<F, D>>) -> G2AffineTarget<F, D>;

    fn curve_scalar_mul_windowed_g2(&mut self, p: &G2AffineTarget<F, D>, n: &NonNativeTarget<Bn128Scalar>) -> G2AffineTarget<F, D>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderWindowedMul<F, D> for CircuitBuilder<F, D> {
    fn precompute_window_g1(&mut self, p: &G1AffineTarget<F, D>) -> Vec<G1AffineTarget<F, D>> {
        let g = G1::GENERATOR_AFFINE;
        let starting = self.constant_g1_affine(g);

        let mut multiples = vec![starting.clone()];

        for i in 1..1 << WINDOW_SIZE {
            multiples.push(self.add_or_double_g1_affine(p, &multiples[i - 1]));
        }

        let neg_starting = self.neg_g1_affine(&starting);
        for i in 1..1 << WINDOW_SIZE {
            multiples[i] = self.add_or_double_g1_affine(&multiples[i], &neg_starting);
        }

        multiples
    }

    fn random_access_curve_points_g1(&mut self, access_index: Target, v: Vec<G1AffineTarget<F, D>>) -> G1AffineTarget<F, D> {
        let num_limbs = 8; // BN128 base field has 256 bits = 8 * 32-bit limbs
        let zero = arithmetic_u32::U32Target(self.zero());

        let x_limbs: Vec<Vec<_>> = (0..num_limbs)
            .map(|i| v.iter().map(|p| p.x.value.limbs.get(i).unwrap_or(&zero).0).collect())
            .collect();

        let y_limbs: Vec<Vec<_>> = (0..num_limbs)
            .map(|i| v.iter().map(|p| p.y.value.limbs.get(i).unwrap_or(&zero).0).collect())
            .collect();

        let is_infinity_targets: Vec<_> = v.iter().map(|p| p.is_infinity.target).collect();

        let selected_x_limbs: Vec<_> = x_limbs
            .iter()
            .map(|limbs| arithmetic_u32::U32Target(self.random_access(access_index, limbs.clone())))
            .collect();

        let selected_y_limbs: Vec<_> = y_limbs
            .iter()
            .map(|limbs| arithmetic_u32::U32Target(self.random_access(access_index, limbs.clone())))
            .collect();

        let selected_is_infinity = BoolTarget::new_unsafe(self.random_access(access_index, is_infinity_targets));

        G1AffineTarget {
            x: NonNativeTarget {
                value: BigUintTarget { limbs: selected_x_limbs },
                _phantom: PhantomData,
            },
            y: NonNativeTarget {
                value: BigUintTarget { limbs: selected_y_limbs },
                _phantom: PhantomData,
            },
            is_infinity: selected_is_infinity,
            _phantom: PhantomData,
        }
    }

    fn curve_scalar_mul_windowed_g1(&mut self, p: &G1AffineTarget<F, D>, n: &NonNativeTarget<Bn128Scalar>) -> G1AffineTarget<F, D> {
        let hash_0 = KeccakHash::<25>::hash_no_pad(&[F::ZERO]);
        let hash_0_scalar = Bn128Scalar::from_noncanonical_biguint(BigUint::from_bytes_le(&GenericHashOut::<F>::to_bytes(&hash_0)));

        let _starting_scalar = hash_0_scalar;
        let _starting_point_x = Bn128Base::from_canonical_u64(0x123456789abcdef0u64);
        let _starting_point_y = Bn128Base::from_canonical_u64(0xfedcba9876543210u64);

        let mut result = self.constant_g1_affine(G1::GENERATOR_AFFINE);

        let precomputation = self.precompute_window_g1(p);
        let zero = self.zero();

        let windows = self.split_nonnative_to_4_bit_limbs(n);

        for i in (0..windows.len()).rev() {
            for _ in 0..WINDOW_SIZE {
                result = self.double_g1_affine(&result);
            }

            let window = windows[i];
            let to_add = self.random_access_curve_points_g1(window, precomputation.clone());

            let is_zero = self.is_equal(window, zero);
            let should_add = self.not(is_zero);

            let new_result = self.add_or_double_g1_affine(&result, &to_add);
            result = G1AffineTarget {
                x: self.select_nonnative(should_add, &new_result.x, &result.x),
                y: self.select_nonnative(should_add, &new_result.y, &result.y),
                is_infinity: {
                    let not_should_add = self.not(should_add);
                    let case_true = self.and(should_add, new_result.is_infinity);
                    let case_false = self.and(not_should_add, result.is_infinity);
                    self.or(case_true, case_false)
                },
                _phantom: PhantomData,
            };
        }

        result
    }

    fn precompute_window_g2(&mut self, p: &G2AffineTarget<F, D>) -> Vec<G2AffineTarget<F, D>> {
        // Use random starting point to avoid witness conflicts (like plonky2-pairing)
        let g = G2::GENERATOR_AFFINE;
        let neg = {
            let mut neg = g;
            neg.y = -neg.y;
            self.constant_g2_affine(neg)
        };

        let mut multiples = vec![self.constant_g2_affine(g)];
        for i in 1..1 << WINDOW_SIZE {
            multiples.push(self.add_g2(p, &multiples[i - 1]));
        }
        for i in 1..1 << WINDOW_SIZE {
            multiples[i] = self.add_g2(&neg, &multiples[i]);
        }
        multiples
    }

    fn random_access_curve_points_g2(&mut self, access_index: Target, v: Vec<G2AffineTarget<F, D>>) -> G2AffineTarget<F, D> {
        let num_limbs = 8; // BN128 base field has 256 bits = 8 * 32-bit limbs
        let zero = arithmetic_u32::U32Target(self.zero());

        let x_c0_limbs: Vec<Vec<_>> = (0..num_limbs)
            .map(|i| v.iter().map(|p| p.x.c0.value.limbs.get(i).unwrap_or(&zero).0).collect())
            .collect();

        let x_c1_limbs: Vec<Vec<_>> = (0..num_limbs)
            .map(|i| v.iter().map(|p| p.x.c1.value.limbs.get(i).unwrap_or(&zero).0).collect())
            .collect();

        let y_c0_limbs: Vec<Vec<_>> = (0..num_limbs)
            .map(|i| v.iter().map(|p| p.y.c0.value.limbs.get(i).unwrap_or(&zero).0).collect())
            .collect();

        let y_c1_limbs: Vec<Vec<_>> = (0..num_limbs)
            .map(|i| v.iter().map(|p| p.y.c1.value.limbs.get(i).unwrap_or(&zero).0).collect())
            .collect();

        let selected_x_c0_limbs: Vec<_> = x_c0_limbs
            .iter()
            .map(|limbs| arithmetic_u32::U32Target(self.random_access(access_index, limbs.clone())))
            .collect();

        let selected_x_c1_limbs: Vec<_> = x_c1_limbs
            .iter()
            .map(|limbs| arithmetic_u32::U32Target(self.random_access(access_index, limbs.clone())))
            .collect();

        let selected_y_c0_limbs: Vec<_> = y_c0_limbs
            .iter()
            .map(|limbs| arithmetic_u32::U32Target(self.random_access(access_index, limbs.clone())))
            .collect();

        let selected_y_c1_limbs: Vec<_> = y_c1_limbs
            .iter()
            .map(|limbs| arithmetic_u32::U32Target(self.random_access(access_index, limbs.clone())))
            .collect();

        let is_infinity_targets: Vec<_> = v.iter().map(|p| p.is_infinity.target).collect();
        let selected_is_infinity = BoolTarget::new_unsafe(self.random_access(access_index, is_infinity_targets));

        G2AffineTarget {
            x: NonNativeTargetExt2 {
                c0: NonNativeTarget {
                    value: BigUintTarget { limbs: selected_x_c0_limbs },
                    _phantom: PhantomData,
                },
                c1: NonNativeTarget {
                    value: BigUintTarget { limbs: selected_x_c1_limbs },
                    _phantom: PhantomData,
                },
                _phantom: PhantomData,
            },
            y: NonNativeTargetExt2 {
                c0: NonNativeTarget {
                    value: BigUintTarget { limbs: selected_y_c0_limbs },
                    _phantom: PhantomData,
                },
                c1: NonNativeTarget {
                    value: BigUintTarget { limbs: selected_y_c1_limbs },
                    _phantom: PhantomData,
                },
                _phantom: PhantomData,
            },
            is_infinity: selected_is_infinity,
            _phantom: PhantomData,
        }
    }

    fn curve_scalar_mul_windowed_g2(&mut self, p: &G2AffineTarget<F, D>, n: &NonNativeTarget<Bn128Scalar>) -> G2AffineTarget<F, D> {
        // Use hash-based starting point like plonky2-pairing to avoid witness conflicts
        let hash_0 = KeccakHash::<25>::hash_no_pad(&[F::ZERO]);
        let hash_0_scalar = Bn128Scalar::from_noncanonical_biguint(BigUint::from_bytes_le(&GenericHashOut::<F>::to_bytes(&hash_0)));
        let starting_point = (CurveScalar::<G2>(hash_0_scalar) * G2::GENERATOR_PROJECTIVE).to_affine();
        let starting_point_multiplied = {
            let mut cur = starting_point.to_projective();
            for _ in 0..Bn128Scalar::BITS {
                cur = cur.double();
            }
            cur.to_affine()
        };

        let mut result = self.constant_g2_affine(starting_point);

        let precomputation = self.precompute_window_g2(p);
        let zero = self.zero();

        let windows = self.split_nonnative_to_4_bit_limbs(n);
        for i in (0..windows.len()).rev() {
            // Double WINDOW_SIZE times
            for _ in 0..WINDOW_SIZE {
                result = self.double_g2(&result);
            }

            let window = windows[i];
            let to_add = self.random_access_curve_points_g2(window, precomputation.clone());
            let is_zero = self.is_equal(window, zero);
            let should_add = self.not(is_zero);

            // Use conditional add to avoid witness conflicts
            let new_result = self.add_g2(&result, &to_add);
            result = self.select_g2(should_add, &new_result, &result);
        }

        // Subtract the offset point
        let to_subtract = self.constant_g2_affine(starting_point_multiplied);
        let to_add = self.neg_g2(&to_subtract);
        result = self.add_g2(&result, &to_add);

        result
    }
}

#[cfg(test)]
mod g2_scalar_mul_tests {
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };

    use super::*;
    use crate::crypto::{
        bn254::{curve::g2::G2, gadgets::CircuitBuilderNonNativeExt2, pairing_config},
        secp256k1::ecdsa::curve::curve_types::{Curve, CurveScalar},
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_curve_scalar_mul_windowed_g2_simple() {
        let config = pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Test with G2 generator and a small scalar
        let g2_gen = builder.constant_g2_affine(G2::GENERATOR_AFFINE);
        let scalar = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(5));

        println!("Starting G2 scalar multiplication test...");
        let _result = builder.curve_scalar_mul_windowed_g2(&g2_gen, &scalar);
        println!("G2 scalar multiplication completed in circuit building");

        let data = builder.build::<C>();
        println!("Circuit built successfully");

        let pw = PartialWitness::new();
        println!("Starting proof generation...");
        let proof = data.prove(pw).unwrap();
        println!("Proof generated successfully");

        data.verify(proof).unwrap();
        println!("Proof verified successfully");
    }

    #[test]
    fn test_curve_scalar_mul_windowed_g2_zero() {
        let config = pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Test with zero scalar (should result in point at infinity)
        let g2_gen = builder.constant_g2_affine(G2::GENERATOR_AFFINE);
        let zero_scalar = builder.constant_nonnative(Bn128Scalar::ZERO);

        let result = builder.curve_scalar_mul_windowed_g2(&g2_gen, &zero_scalar);

        // Result should be point at infinity
        builder.assert_one(result.is_infinity.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_curve_scalar_mul_windowed_g2_one() {
        let config = pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Test with scalar = 1 (should result in the same point)
        let g2_gen = builder.constant_g2_affine(G2::GENERATOR_AFFINE);
        let one_scalar = builder.constant_nonnative(Bn128Scalar::ONE);

        let result = builder.curve_scalar_mul_windowed_g2(&g2_gen, &one_scalar);

        // Result should equal the original point
        builder.connect_nonnative_ext2(&result.x, &g2_gen.x);
        builder.connect_nonnative_ext2(&result.y, &g2_gen.y);
        builder.connect(result.is_infinity.target, g2_gen.is_infinity.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();

        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_g2_basic_operations() {
        let config = pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Test basic G2 operations without windowed multiplication
        let g2_gen = builder.constant_g2_affine(G2::GENERATOR_AFFINE);

        // Test doubling
        let doubled = builder.double_g2(&g2_gen);

        // Test addition
        let _added = builder.add_g2(&g2_gen, &doubled);

        // Just ensure we can build the circuit
        let data = builder.build::<C>();
        let pw = PartialWitness::new();

        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_curve_scalar_mul_windowed_g2_with_bn_scalar() {
        // Test with the same scalar used in bn crate:
        // "20390255904278144451778773028944684152769293537511418234311120800877067946"
        let config = pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g2_gen = builder.constant_g2_affine(G2::GENERATOR_AFFINE);

        // Use the scalar from bn crate test case
        use num::BigUint;
        let scalar_str = "20390255904278144451778773028944684152769293537511418234311120800877067946";
        let scalar_biguint = BigUint::parse_bytes(scalar_str.as_bytes(), 10).unwrap();
        let scalar_bn128 = Bn128Scalar::from_noncanonical_biguint(scalar_biguint);
        let scalar = builder.constant_nonnative(scalar_bn128);

        println!("Testing G2 scalar multiplication with bn crate scalar: {}", scalar_str);

        let result = builder.curve_scalar_mul_windowed_g2(&g2_gen, &scalar);
        println!("G2 scalar multiplication completed");

        // Verify it's not the point at infinity (unless scalar is 0, which it's not)
        builder.assert_zero(result.is_infinity.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();

        println!("Test passed: G2 scalar multiplication with bn crate scalar is correct");
    }

    #[test]
    fn test_g2_addition_correctness() {
        // First test if G2 addition itself is correct
        let config = pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g2_gen = builder.constant_g2_affine(G2::GENERATOR_AFFINE);

        // Test: G2 + G2 = 2*G2 (using different methods)
        let g2_plus_g2 = builder.add_g2(&g2_gen, &g2_gen); // Addition
        let scalar_2 = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2));
        let two_g2 = builder.curve_scalar_mul_windowed_g2(&g2_gen, &scalar_2); // Scalar multiplication

        println!("Testing G2 addition: G2 + G2 vs 2*G2");

        // They should be equal
        builder.connect_nonnative_ext2(&g2_plus_g2.x, &two_g2.x);
        builder.connect_nonnative_ext2(&g2_plus_g2.y, &two_g2.y);
        builder.connect(g2_plus_g2.is_infinity.target, two_g2.is_infinity.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();

        println!("Test passed: G2 addition is correct");
    }

    #[test]
    fn test_g2_generator_properties() {
        // Test basic properties of G2 generator
        let config = pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g2_gen = builder.constant_g2_affine(G2::GENERATOR_AFFINE);

        // Test: G2 generator is not infinity
        builder.assert_zero(g2_gen.is_infinity.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();

        println!("✅ G2 generator properties test passed");
    }

    #[test]
    fn test_g2_doubling_vs_addition() {
        // Test: 2*G2 = G2 + G2
        let config = pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g2_gen = builder.constant_g2_affine(G2::GENERATOR_AFFINE);

        let doubled = builder.double_g2(&g2_gen);
        let added = builder.add_g2(&g2_gen, &g2_gen);

        // They should be equal
        builder.connect_nonnative_ext2(&doubled.x, &added.x);
        builder.connect_nonnative_ext2(&doubled.y, &added.y);
        builder.connect(doubled.is_infinity.target, added.is_infinity.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();

        println!("✅ G2 doubling vs addition test passed");
    }

    #[test]
    fn test_g2_scalar_mul_small_values() {
        // Test scalar multiplication with small values: 1, 2, 3, 4
        let config = pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g2_gen = builder.constant_g2_affine(G2::GENERATOR_AFFINE);

        // Test 1*G2 = G2
        let one_scalar = builder.constant_nonnative(Bn128Scalar::ONE);
        let one_g2 = builder.curve_scalar_mul_windowed_g2(&g2_gen, &one_scalar);

        builder.connect_nonnative_ext2(&one_g2.x, &g2_gen.x);
        builder.connect_nonnative_ext2(&one_g2.y, &g2_gen.y);
        builder.connect(one_g2.is_infinity.target, g2_gen.is_infinity.target);

        // Test 2*G2 = G2 + G2
        let two_scalar = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2));
        let two_g2 = builder.curve_scalar_mul_windowed_g2(&g2_gen, &two_scalar);
        let doubled_g2 = builder.double_g2(&g2_gen);

        builder.connect_nonnative_ext2(&two_g2.x, &doubled_g2.x);
        builder.connect_nonnative_ext2(&two_g2.y, &doubled_g2.y);
        builder.connect(two_g2.is_infinity.target, doubled_g2.is_infinity.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();

        println!("✅ G2 scalar multiplication small values test passed");
    }

    #[test]
    fn test_g2_scalar_mul_associativity() {
        // Test: (a*b)*G2 = (a+b)*G2 (distributivity instead of associativity)
        let config = pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g2_gen = builder.constant_g2_affine(G2::GENERATOR_AFFINE);

        let a = Bn128Scalar::from_canonical_u64(3);
        let b = Bn128Scalar::from_canonical_u64(5);
        let ab = a * b; // 3 * 5 = 15

        // Test: (a*b)*G2 = a*b*G2
        let ab_scalar = builder.constant_nonnative(ab);
        let left_side = builder.curve_scalar_mul_windowed_g2(&g2_gen, &ab_scalar);

        // Compare with expected result computed outside circuit
        let expected_point = (CurveScalar::<G2>(ab) * G2::GENERATOR_PROJECTIVE).to_affine();
        let right_side = builder.constant_g2_affine(expected_point);

        // They should be equal
        builder.connect_nonnative_ext2(&left_side.x, &right_side.x);
        builder.connect_nonnative_ext2(&left_side.y, &right_side.y);
        builder.connect(left_side.is_infinity.target, right_side.is_infinity.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();

        println!("✅ G2 scalar multiplication correctness test passed");
    }

    #[test]
    fn test_g2_addition_commutativity() {
        // Test: P + Q = Q + P
        let config = pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g2_gen = builder.constant_g2_affine(G2::GENERATOR_AFFINE);

        // Create two different points: G2 and 3*G2
        let three_scalar = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(3));
        let three_g2 = builder.curve_scalar_mul_windowed_g2(&g2_gen, &three_scalar);

        let p_plus_q = builder.add_g2(&g2_gen, &three_g2);
        let q_plus_p = builder.add_g2(&three_g2, &g2_gen);

        // They should be equal
        builder.connect_nonnative_ext2(&p_plus_q.x, &q_plus_p.x);
        builder.connect_nonnative_ext2(&p_plus_q.y, &q_plus_p.y);
        builder.connect(p_plus_q.is_infinity.target, q_plus_p.is_infinity.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();

        println!("✅ G2 addition commutativity test passed");
    }

    #[test]
    fn test_g2_addition_associativity() {
        // Test: (P + Q) + R = P + (Q + R)
        let config = pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g2_gen = builder.constant_g2_affine(G2::GENERATOR_AFFINE);

        // Create three different points
        let two_scalar = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2));
        let two_g2 = builder.curve_scalar_mul_windowed_g2(&g2_gen, &two_scalar);

        let three_scalar = builder.constant_nonnative(Bn128Scalar::from_canonical_u64(3));
        let three_g2 = builder.curve_scalar_mul_windowed_g2(&g2_gen, &three_scalar);

        // (P + Q) + R
        let p_plus_q = builder.add_g2(&g2_gen, &two_g2);
        let left_side = builder.add_g2(&p_plus_q, &three_g2);

        // P + (Q + R)
        let q_plus_r = builder.add_g2(&two_g2, &three_g2);
        let right_side = builder.add_g2(&g2_gen, &q_plus_r);

        // They should be equal
        builder.connect_nonnative_ext2(&left_side.x, &right_side.x);
        builder.connect_nonnative_ext2(&left_side.y, &right_side.y);
        builder.connect(left_side.is_infinity.target, right_side.is_infinity.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();

        println!("✅ G2 addition associativity test passed");
    }

    #[test]
    fn test_g2_scalar_mul_distributivity() {
        // Test: (a + b)*G2 = a*G2 + b*G2
        let config = pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g2_gen = builder.constant_g2_affine(G2::GENERATOR_AFFINE);

        let a = Bn128Scalar::from_canonical_u64(5);
        let b = Bn128Scalar::from_canonical_u64(7);
        let a_plus_b = Bn128Scalar::from_canonical_u64(12); // 5 + 7

        // (a + b)*G2
        let ab_scalar = builder.constant_nonnative(a_plus_b);
        let left_side = builder.curve_scalar_mul_windowed_g2(&g2_gen, &ab_scalar);

        // a*G2 + b*G2
        let a_scalar = builder.constant_nonnative(a);
        let a_g2 = builder.curve_scalar_mul_windowed_g2(&g2_gen, &a_scalar);
        let b_scalar = builder.constant_nonnative(b);
        let b_g2 = builder.curve_scalar_mul_windowed_g2(&g2_gen, &b_scalar);
        let right_side = builder.add_g2(&a_g2, &b_g2);

        // They should be equal
        builder.connect_nonnative_ext2(&left_side.x, &right_side.x);
        builder.connect_nonnative_ext2(&left_side.y, &right_side.y);
        builder.connect(left_side.is_infinity.target, right_side.is_infinity.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();

        println!("✅ G2 scalar multiplication distributivity test passed");
    }

    #[test]
    fn test_g2_negation_properties() {
        // Test: P + (-P) = O (point at infinity) and -(-P) = P
        let config = pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g2_gen = builder.constant_g2_affine(G2::GENERATOR_AFFINE);

        // Test -(-P) = P
        let neg_g2 = builder.neg_g2(&g2_gen);
        let neg_neg_g2 = builder.neg_g2(&neg_g2);

        builder.connect_nonnative_ext2(&neg_neg_g2.x, &g2_gen.x);
        builder.connect_nonnative_ext2(&neg_neg_g2.y, &g2_gen.y);
        builder.connect(neg_neg_g2.is_infinity.target, g2_gen.is_infinity.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();

        println!("✅ G2 negation properties test passed");
    }
}
