use std::marker::PhantomData;

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::crypto::{
    bn254::{
        curve::g1::G1,
        field::{bn128_base::Bn128Base, bn128_scalar::Bn128Scalar},
        gadgets::nonnative_fp::{CircuitBuilderNonNative, NonNativeTarget},
    },
    secp256k1::ecdsa::curve::curve_types::{AffinePoint, Curve},
};

type G1Affine = AffinePoint<G1>;

#[derive(Clone, Debug)]
pub struct G1AffineTarget<F: RichField + Extendable<D>, const D: usize> {
    pub x: NonNativeTarget<Bn128Base>,
    pub y: NonNativeTarget<Bn128Base>,
    pub is_infinity: BoolTarget,
    pub _phantom: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct G1ProjectiveTarget<F: RichField + Extendable<D>, const D: usize> {
    pub x: NonNativeTarget<Bn128Base>,
    pub y: NonNativeTarget<Bn128Base>,
    pub z: NonNativeTarget<Bn128Base>,
    pub _phantom: PhantomData<F>,
}

pub trait CircuitBuilderG1<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_g1_affine_target(&mut self) -> G1AffineTarget<F, D>;

    fn add_virtual_g1_projective_target(&mut self) -> G1ProjectiveTarget<F, D>;

    fn constant_g1_affine(&mut self, point: G1Affine) -> G1AffineTarget<F, D>;

    fn add_g1_affine(&mut self, p1: &G1AffineTarget<F, D>, p2: &G1AffineTarget<F, D>) -> G1AffineTarget<F, D>;

    fn add_or_double_g1_affine(&mut self, p1: &G1AffineTarget<F, D>, p2: &G1AffineTarget<F, D>) -> G1AffineTarget<F, D>;

    fn double_g1_affine(&mut self, p: &G1AffineTarget<F, D>) -> G1AffineTarget<F, D>;

    fn neg_g1_affine(&mut self, p: &G1AffineTarget<F, D>) -> G1AffineTarget<F, D>;

    fn scalar_mul_g1(&mut self, point: &G1AffineTarget<F, D>, scalar: &NonNativeTarget<Bn128Scalar>) -> G1AffineTarget<F, D>;

    fn g1_msm(&mut self, points: &[G1AffineTarget<F, D>], scalars: &[NonNativeTarget<Bn128Scalar>]) -> G1AffineTarget<F, D>;

    fn assert_g1_on_curve(&mut self, point: &G1AffineTarget<F, D>);

    fn is_equal_g1(&mut self, p1: &G1AffineTarget<F, D>, p2: &G1AffineTarget<F, D>) -> BoolTarget;

    fn select_g1(&mut self, condition: BoolTarget, true_point: &G1AffineTarget<F, D>, false_point: &G1AffineTarget<F, D>) -> G1AffineTarget<F, D>;

    fn g1_projective_to_affine(&mut self, p: &G1ProjectiveTarget<F, D>) -> G1AffineTarget<F, D>;

    fn g1_affine_to_projective(&mut self, p: &G1AffineTarget<F, D>) -> G1ProjectiveTarget<F, D>;

    fn g1_generator(&mut self) -> G1AffineTarget<F, D>;

    fn connect_g1(&mut self, a: &G1AffineTarget<F, D>, b: &G1AffineTarget<F, D>);
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderG1<F, D> for CircuitBuilder<F, D> {
    fn add_virtual_g1_affine_target(&mut self) -> G1AffineTarget<F, D> {
        G1AffineTarget {
            x: self.add_virtual_nonnative_target(),
            y: self.add_virtual_nonnative_target(),
            is_infinity: self.add_virtual_bool_target_safe(),
            _phantom: PhantomData,
        }
    }

    fn add_virtual_g1_projective_target(&mut self) -> G1ProjectiveTarget<F, D> {
        G1ProjectiveTarget {
            x: self.add_virtual_nonnative_target(),
            y: self.add_virtual_nonnative_target(),
            z: self.add_virtual_nonnative_target(),
            _phantom: PhantomData,
        }
    }

    fn constant_g1_affine(&mut self, point: G1Affine) -> G1AffineTarget<F, D> {
        G1AffineTarget {
            x: self.constant_nonnative(point.x),
            y: self.constant_nonnative(point.y),
            is_infinity: self.constant_bool(point.zero),
            _phantom: PhantomData,
        }
    }

    fn add_g1_affine(&mut self, p1: &G1AffineTarget<F, D>, p2: &G1AffineTarget<F, D>) -> G1AffineTarget<F, D> {
        let u = self.sub_nonnative(&p2.y, &p1.y);
        let v = self.sub_nonnative(&p2.x, &p1.x);
        let v_inv = self.inv_nonnative(&v);
        let s = self.mul_nonnative(&u, &v_inv);
        let s_squared = self.square_nonnative(&s);
        let x_sum = self.add_nonnative(&p2.x, &p1.x);
        let x3 = self.sub_nonnative(&s_squared, &x_sum);
        let x_diff = self.sub_nonnative(&p1.x, &x3);
        let prod = self.mul_nonnative(&s, &x_diff);
        let y3 = self.sub_nonnative(&prod, &p1.y);

        G1AffineTarget {
            x: x3,
            y: y3,
            is_infinity: self._false(),
            _phantom: PhantomData,
        }
    }

    fn add_or_double_g1_affine(&mut self, p1: &G1AffineTarget<F, D>, p2: &G1AffineTarget<F, D>) -> G1AffineTarget<F, D> {
        let p1_is_inf = p1.is_infinity;
        let p2_is_inf = p2.is_infinity;

        let x_equal = self.is_equal_nonnative(&p1.x, &p2.x);

        let y_equal = self.is_equal_nonnative(&p1.y, &p2.y);
        let should_double = self.and(x_equal, y_equal);

        let neg_p2_y = self.neg_nonnative(&p2.y);
        let y_opposite = self.is_equal_nonnative(&p1.y, &neg_p2_y);
        let should_be_infinity_from_addition = self.and(x_equal, y_opposite);

        let doubled = self.double_g1_affine(p1);

        let v = self.sub_nonnative(&p2.x, &p1.x);
        let one = self.one_nonnative();
        let v_safe = self.select_nonnative(x_equal, &one, &v);
        let v_inv = self.inv_nonnative(&v_safe);

        let u = self.sub_nonnative(&p2.y, &p1.y);
        let s = self.mul_nonnative(&u, &v_inv);
        let s_squared = self.square_nonnative(&s);
        let x_sum = self.add_nonnative(&p2.x, &p1.x);
        let x3_add = self.sub_nonnative(&s_squared, &x_sum);
        let x_diff = self.sub_nonnative(&p1.x, &x3_add);
        let prod = self.mul_nonnative(&s, &x_diff);
        let y3_add = self.sub_nonnative(&prod, &p1.y);

        let zero = self.zero_nonnative();
        let infinity_point = G1AffineTarget {
            x: zero.clone(),
            y: zero.clone(),
            is_infinity: self._true(),
            _phantom: PhantomData,
        };

        let false_target = self._false().target;
        let result_if_not_special = G1AffineTarget {
            x: self.select_nonnative(should_double, &doubled.x, &x3_add),
            y: self.select_nonnative(should_double, &doubled.y, &y3_add),
            is_infinity: BoolTarget::new_unsafe(self.select(should_double, doubled.is_infinity.target, false_target)),
            _phantom: PhantomData,
        };

        let result_if_p1_inf = p2.clone();

        let result_if_p2_inf = p1.clone();

        let result_if_opposite = infinity_point;

        let mut result = result_if_not_special;
        result = self.select_g1(should_be_infinity_from_addition, &result_if_opposite, &result);
        result = self.select_g1(p2_is_inf, &result_if_p2_inf, &result);
        result = self.select_g1(p1_is_inf, &result_if_p1_inf, &result);

        result
    }

    fn double_g1_affine(&mut self, p: &G1AffineTarget<F, D>) -> G1AffineTarget<F, D> {
        let y_is_zero = self.is_zero_nonnative(&p.y);

        let x_squared = self.square_nonnative(&p.x);
        let two_x_squared = self.add_nonnative(&x_squared, &x_squared);
        let three_x_squared = self.add_nonnative(&x_squared, &two_x_squared);
        let two_y = self.add_nonnative(&p.y, &p.y);

        let one = self.one_nonnative();
        let two_y_safe = self.select_nonnative(y_is_zero, &one, &two_y);
        let slope = self.div_nonnative(&three_x_squared, &two_y_safe);

        let slope_squared = self.square_nonnative(&slope);
        let two_x = self.add_nonnative(&p.x, &p.x);
        let x3 = self.sub_nonnative(&slope_squared, &two_x);

        let x_diff = self.sub_nonnative(&p.x, &x3);
        let y3_temp = self.mul_nonnative(&slope, &x_diff);
        let y3 = self.sub_nonnative(&y3_temp, &p.y);

        let zero = self.zero_nonnative();

        let true_target = self._true().target;
        let false_target = self._false().target;
        G1AffineTarget {
            x: self.select_nonnative(y_is_zero, &zero, &x3),
            y: self.select_nonnative(y_is_zero, &zero, &y3),
            is_infinity: BoolTarget::new_unsafe(self.select(y_is_zero, true_target, false_target)),
            _phantom: PhantomData,
        }
    }

    fn neg_g1_affine(&mut self, p: &G1AffineTarget<F, D>) -> G1AffineTarget<F, D> {
        G1AffineTarget {
            x: p.x.clone(),
            y: self.neg_nonnative(&p.y),
            is_infinity: p.is_infinity,
            _phantom: PhantomData,
        }
    }

    fn scalar_mul_g1(&mut self, point: &G1AffineTarget<F, D>, scalar: &NonNativeTarget<Bn128Scalar>) -> G1AffineTarget<F, D> {
        let bits = self.split_nonnative_to_bits(scalar);

        let zero = self.zero_nonnative();
        let one = self.one_nonnative();
        let mut result = G1AffineTarget {
            x: zero.clone(),
            y: one.clone(),
            is_infinity: self._true(),
            _phantom: PhantomData,
        };

        let mut two_i_times_p = point.clone();

        for &bit in bits.iter() {
            let result_is_inf = result.is_infinity;
            let term_is_inf = two_i_times_p.is_infinity;

            let new_result_if_result_inf_and_bit_1 = two_i_times_p.clone();

            let _new_result_if_term_inf_and_bit_1 = result.clone();

            let new_result_normal = self.add_or_double_g1_affine(&result, &two_i_times_p);

            let not_term_inf = self.not(term_is_inf);
            let bit_and_not_term_inf = self.and(bit, not_term_inf);
            let bit_and_result_inf = self.and(bit, result_is_inf);

            let mut new_result = result.clone(); // Default: don't add (bit = 0)

            let not_result_inf = self.not(result_is_inf);
            let should_add_normal = self.and(bit_and_not_term_inf, not_result_inf);
            new_result = self.select_g1(should_add_normal, &new_result_normal, &new_result);

            new_result = self.select_g1(bit_and_result_inf, &new_result_if_result_inf_and_bit_1, &new_result);

            result = new_result;
            two_i_times_p = self.double_g1_affine(&two_i_times_p);
        }

        result
    }

    fn g1_msm(&mut self, points: &[G1AffineTarget<F, D>], scalars: &[NonNativeTarget<Bn128Scalar>]) -> G1AffineTarget<F, D> {
        assert_eq!(points.len(), scalars.len(), "Points and scalars must have the same length");
        assert!(!points.is_empty(), "Cannot compute MSM with empty inputs");

        let zero = self.zero_nonnative();
        let one = self.one_nonnative();
        let mut result = G1AffineTarget {
            x: zero.clone(),
            y: one.clone(), // (0, 1) represents point at infinity in affine coordinates
            is_infinity: self._true(),
            _phantom: PhantomData,
        };

        for i in 0..points.len() {
            let term = self.scalar_mul_g1(&points[i], &scalars[i]);

            let result_is_inf = result.is_infinity;
            let term_is_inf = term.is_infinity;

            let new_result_if_result_inf = term.clone();

            let new_result_if_term_inf = result.clone();

            let new_result_normal = self.add_or_double_g1_affine(&result, &term);

            let mut new_result = new_result_normal;
            new_result = self.select_g1(term_is_inf, &new_result_if_term_inf, &new_result);
            new_result = self.select_g1(result_is_inf, &new_result_if_result_inf, &new_result);

            result = new_result;
        }

        result
    }

    fn assert_g1_on_curve(&mut self, point: &G1AffineTarget<F, D>) {
        let y_squared = self.square_nonnative(&point.y);
        let x_squared = self.square_nonnative(&point.x);
        let x_cubed = self.mul_nonnative(&x_squared, &point.x);
        let three = self.constant_nonnative(Bn128Base::from_canonical_u64(3));
        let rhs = self.add_nonnative(&x_cubed, &three);

        self.connect_nonnative(&y_squared, &rhs);
    }

    fn is_equal_g1(&mut self, p1: &G1AffineTarget<F, D>, p2: &G1AffineTarget<F, D>) -> BoolTarget {
        let x_equal = self.is_equal_nonnative(&p1.x, &p2.x);
        let y_equal = self.is_equal_nonnative(&p1.y, &p2.y);
        let infinity_equal = self.is_equal(p1.is_infinity.target, p2.is_infinity.target);

        let coords_equal = self.and(x_equal, y_equal);
        self.and(coords_equal, infinity_equal)
    }

    fn select_g1(&mut self, condition: BoolTarget, true_point: &G1AffineTarget<F, D>, false_point: &G1AffineTarget<F, D>) -> G1AffineTarget<F, D> {
        G1AffineTarget {
            x: self.select_nonnative(condition, &true_point.x, &false_point.x),
            y: self.select_nonnative(condition, &true_point.y, &false_point.y),
            is_infinity: BoolTarget::new_unsafe(self.select(condition, true_point.is_infinity.target, false_point.is_infinity.target)),
            _phantom: PhantomData,
        }
    }

    fn g1_projective_to_affine(&mut self, p: &G1ProjectiveTarget<F, D>) -> G1AffineTarget<F, D> {
        // Following ark-r1cs-std approach
        // inv_nonnative now handles zero case properly
        let z_is_zero = self.is_zero_nonnative(&p.z);
        let zero = self.zero_nonnative();

        // Use inv_nonnative which follows ark-r1cs-std approach internally
        let z_inv = self.inv_nonnative(&p.z);

        // Compute affine coordinates
        let x_non_zero = self.mul_nonnative(&p.x, &z_inv);
        let y_non_zero = self.mul_nonnative(&p.y, &z_inv);

        // Select based on whether z is zero
        let x_affine = self.select_nonnative(z_is_zero, &zero, &x_non_zero);
        let y_affine = self.select_nonnative(z_is_zero, &zero, &y_non_zero);

        G1AffineTarget {
            x: x_affine,
            y: y_affine,
            is_infinity: z_is_zero,
            _phantom: PhantomData,
        }
    }

    fn g1_affine_to_projective(&mut self, p: &G1AffineTarget<F, D>) -> G1ProjectiveTarget<F, D> {
        let one = self.one_nonnative();
        let zero = self.zero_nonnative();

        G1ProjectiveTarget {
            x: self.select_nonnative(p.is_infinity, &zero, &p.x),
            y: self.select_nonnative(p.is_infinity, &one, &p.y),
            z: self.select_nonnative(p.is_infinity, &zero, &one),
            _phantom: PhantomData,
        }
    }

    fn g1_generator(&mut self) -> G1AffineTarget<F, D> {
        self.constant_g1_affine(G1::GENERATOR_AFFINE)
    }

    fn connect_g1(&mut self, a: &G1AffineTarget<F, D>, b: &G1AffineTarget<F, D>) {
        self.connect_nonnative(&a.x, &b.x);
        self.connect_nonnative(&a.y, &b.y);
        self.connect(a.is_infinity.target, b.is_infinity.target);
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::types::PrimeField,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };

    use super::*;
    use crate::crypto::{bn254::gadgets::nonnative_fp::CircuitBuilderNonNative, secp256k1::ecdsa::gadgets::biguint::WitnessBigUint};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_g1_projective_to_affine_non_zero() -> Result<(), anyhow::Error> {
        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Test with a non-zero point
        let g1_gen = G1::GENERATOR_PROJECTIVE;

        // Create projective point targets
        let x = builder.constant_nonnative(g1_gen.x);
        let y = builder.constant_nonnative(g1_gen.y);
        let z = builder.constant_nonnative(g1_gen.z);

        let proj = G1ProjectiveTarget {
            x,
            y,
            z,
            _phantom: PhantomData,
        };

        // Convert to affine
        let affine = builder.g1_projective_to_affine(&proj);

        // The result should be the generator in affine form
        let expected = builder.constant_g1_affine(G1::GENERATOR_AFFINE);
        builder.connect_g1(&affine, &expected);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw)?;
        data.verify(proof)?;
        Ok(())
    }

    #[test]
    fn test_g1_projective_to_affine_infinity() -> Result<(), anyhow::Error> {
        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Test with infinity point (z = 0)
        let x = builder.constant_nonnative(Bn128Base::ONE);
        let y = builder.constant_nonnative(Bn128Base::ONE);
        let z = builder.constant_nonnative(Bn128Base::ZERO);

        let proj = G1ProjectiveTarget {
            x,
            y,
            z,
            _phantom: PhantomData,
        };

        // Convert to affine
        let affine = builder.g1_projective_to_affine(&proj);

        // The result should be infinity
        let zero = builder.zero_nonnative();
        builder.connect_nonnative(&affine.x, &zero);
        builder.connect_nonnative(&affine.y, &zero);
        let true_target = builder._true().target;
        builder.connect(affine.is_infinity.target, true_target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw)?;
        data.verify(proof)?;
        Ok(())
    }

    #[test]
    fn test_g1_projective_to_affine_witness_generator() -> Result<(), anyhow::Error> {
        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Test with witness values for generator point
        let x_target = builder.add_virtual_nonnative_target();
        let y_target = builder.add_virtual_nonnative_target();
        let z_target = builder.add_virtual_nonnative_target();

        let proj = G1ProjectiveTarget {
            x: x_target.clone(),
            y: y_target.clone(),
            z: z_target.clone(),
            _phantom: PhantomData,
        };

        // Convert to affine
        let affine = builder.g1_projective_to_affine(&proj);

        // Create expected affine result
        let expected_x_target = builder.add_virtual_nonnative_target();
        let expected_y_target = builder.add_virtual_nonnative_target();
        let expected_infinity = builder.add_virtual_bool_target_safe();

        builder.connect_nonnative(&affine.x, &expected_x_target);
        builder.connect_nonnative(&affine.y, &expected_y_target);
        builder.connect(affine.is_infinity.target, expected_infinity.target);

        let data = builder.build::<C>();

        // Test with generator point
        let mut pw = PartialWitness::new();
        let g1_gen = G1::GENERATOR_PROJECTIVE;
        let g1_affine = G1::GENERATOR_AFFINE;

        pw.set_biguint_target(&x_target.value, &g1_gen.x.to_canonical_biguint())?;
        pw.set_biguint_target(&y_target.value, &g1_gen.y.to_canonical_biguint())?;
        pw.set_biguint_target(&z_target.value, &g1_gen.z.to_canonical_biguint())?;
        pw.set_biguint_target(&expected_x_target.value, &g1_affine.x.to_canonical_biguint())?;
        pw.set_biguint_target(&expected_y_target.value, &g1_affine.y.to_canonical_biguint())?;
        pw.set_bool_target(expected_infinity, false)?;

        let proof = data.prove(pw)?;
        data.verify(proof)?;
        Ok(())
    }

    #[test]
    fn test_g1_projective_to_affine_witness_infinity() -> Result<(), anyhow::Error> {
        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Test with witness values for infinity point
        let x_target = builder.add_virtual_nonnative_target();
        let y_target = builder.add_virtual_nonnative_target();
        let z_target = builder.add_virtual_nonnative_target();

        let proj = G1ProjectiveTarget {
            x: x_target.clone(),
            y: y_target.clone(),
            z: z_target.clone(),
            _phantom: PhantomData,
        };

        // Convert to affine
        let affine = builder.g1_projective_to_affine(&proj);

        // Create expected affine result
        let expected_x_target = builder.add_virtual_nonnative_target();
        let expected_y_target = builder.add_virtual_nonnative_target();
        let expected_infinity = builder.add_virtual_bool_target_safe();

        builder.connect_nonnative(&affine.x, &expected_x_target);
        builder.connect_nonnative(&affine.y, &expected_y_target);
        builder.connect(affine.is_infinity.target, expected_infinity.target);

        let data = builder.build::<C>();

        // Test with infinity point
        let mut pw = PartialWitness::new();
        pw.set_biguint_target(&x_target.value, &Bn128Base::ONE.to_canonical_biguint())?;
        pw.set_biguint_target(&y_target.value, &Bn128Base::ONE.to_canonical_biguint())?;
        pw.set_biguint_target(&z_target.value, &Bn128Base::ZERO.to_canonical_biguint())?;
        pw.set_biguint_target(&expected_x_target.value, &Bn128Base::ZERO.to_canonical_biguint())?;
        pw.set_biguint_target(&expected_y_target.value, &Bn128Base::ZERO.to_canonical_biguint())?;
        pw.set_bool_target(expected_infinity, true)?;

        let proof = data.prove(pw)?;
        data.verify(proof)?;
        Ok(())
    }
}
