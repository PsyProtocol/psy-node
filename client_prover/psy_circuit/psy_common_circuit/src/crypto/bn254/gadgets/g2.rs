use std::marker::PhantomData;

use plonky2::{field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget, plonk::circuit_builder::CircuitBuilder};

use crate::crypto::bn254::{
    curve::G2Affine,
    field::bn128_base::Bn128Base,
    gadgets::{
        nonnative_fp::CircuitBuilderNonNative,
        nonnative_fp2::{CircuitBuilderNonNativeExt2, NonNativeTargetExt2},
    },
};

#[derive(Clone, Debug)]
pub struct G2AffineTarget<F: RichField + Extendable<D>, const D: usize> {
    pub x: NonNativeTargetExt2<Bn128Base>,
    pub y: NonNativeTargetExt2<Bn128Base>,
    pub is_infinity: BoolTarget,
    pub _phantom: PhantomData<F>,
}

pub trait CircuitBuilderG2<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_g2_affine_target(&mut self) -> G2AffineTarget<F, D>;

    fn constant_g2_affine(&mut self, point: G2Affine) -> G2AffineTarget<F, D>;

    fn is_equal_g2(&mut self, p1: &G2AffineTarget<F, D>, p2: &G2AffineTarget<F, D>) -> BoolTarget;

    fn select_g2(&mut self, condition: BoolTarget, true_point: &G2AffineTarget<F, D>, false_point: &G2AffineTarget<F, D>) -> G2AffineTarget<F, D>;

    fn add_g2(&mut self, a: &G2AffineTarget<F, D>, b: &G2AffineTarget<F, D>) -> G2AffineTarget<F, D>;

    fn add_or_double_g2(&mut self, a: &G2AffineTarget<F, D>, b: &G2AffineTarget<F, D>) -> G2AffineTarget<F, D>;

    fn double_g2(&mut self, p: &G2AffineTarget<F, D>) -> G2AffineTarget<F, D>;

    fn neg_g2(&mut self, p: &G2AffineTarget<F, D>) -> G2AffineTarget<F, D>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderG2<F, D> for CircuitBuilder<F, D> {
    fn add_virtual_g2_affine_target(&mut self) -> G2AffineTarget<F, D> {
        G2AffineTarget {
            x: self.add_virtual_nonnative_ext2_target(),
            y: self.add_virtual_nonnative_ext2_target(),
            is_infinity: self.add_virtual_bool_target_safe(),
            _phantom: PhantomData,
        }
    }

    fn constant_g2_affine(&mut self, point: G2Affine) -> G2AffineTarget<F, D> {
        G2AffineTarget {
            x: self.constant_nonnative_ext2(point.x),
            y: self.constant_nonnative_ext2(point.y),
            is_infinity: self.constant_bool(point.zero),
            _phantom: PhantomData,
        }
    }

    fn is_equal_g2(&mut self, p1: &G2AffineTarget<F, D>, p2: &G2AffineTarget<F, D>) -> BoolTarget {
        let x_equal = self.is_equal_ext2(&p1.x, &p2.x);
        let y_equal = self.is_equal_ext2(&p1.y, &p2.y);
        let infinity_equal = self.is_equal(p1.is_infinity.target, p2.is_infinity.target);

        let coords_equal = self.and(x_equal, y_equal);
        self.and(coords_equal, infinity_equal)
    }

    fn select_g2(&mut self, condition: BoolTarget, true_point: &G2AffineTarget<F, D>, false_point: &G2AffineTarget<F, D>) -> G2AffineTarget<F, D> {
        G2AffineTarget {
            x: self.select_ext2(condition, &true_point.x, &false_point.x),
            y: self.select_ext2(condition, &true_point.y, &false_point.y),
            is_infinity: BoolTarget::new_unsafe(self.select(condition, true_point.is_infinity.target, false_point.is_infinity.target)),
            _phantom: PhantomData,
        }
    }

    fn add_g2(&mut self, a: &G2AffineTarget<F, D>, b: &G2AffineTarget<F, D>) -> G2AffineTarget<F, D> {
        // Use the complete addition formula that handles doubling
        self.add_or_double_g2(a, b)
    }

    fn double_g2(&mut self, p: &G2AffineTarget<F, D>) -> G2AffineTarget<F, D> {
        // Check if y is zero (for both components)
        let y0_is_zero = self.is_zero_nonnative(&p.y.c0);
        let y1_is_zero = self.is_zero_nonnative(&p.y.c1);
        let y_is_zero = self.and(y0_is_zero, y1_is_zero);

        let x_squared = self.squared_nonnative_ext2(&p.x);
        let two_x_squared = self.add_nonnative_ext2(&x_squared, &x_squared);
        let three_x_squared = self.add_nonnative_ext2(&x_squared, &two_x_squared);
        let two_y = self.add_nonnative_ext2(&p.y, &p.y);

        let one = self.one_nonnative();
        let zero = self.zero_nonnative();
        let one_ext2 = NonNativeTargetExt2 {
            c0: one,
            c1: zero,
            _phantom: PhantomData,
        };
        let two_y_safe = self.select_ext2(y_is_zero, &one_ext2, &two_y);
        let two_y_inv = self.inv_nonnative_ext2(&two_y_safe);
        let slope = self.mul_nonnative_ext2(&three_x_squared, &two_y_inv);

        let slope_squared = self.squared_nonnative_ext2(&slope);
        let two_x = self.add_nonnative_ext2(&p.x, &p.x);
        let x3 = self.sub_nonnative_ext2(&slope_squared, &two_x);

        let x_diff = self.sub_nonnative_ext2(&p.x, &x3);
        let y3_temp = self.mul_nonnative_ext2(&slope, &x_diff);
        let y3 = self.sub_nonnative_ext2(&y3_temp, &p.y);

        let zero = self.zero_nonnative_ext2();

        let true_target = self._true().target;
        let false_target = self._false().target;
        G2AffineTarget {
            x: self.select_ext2(y_is_zero, &zero, &x3),
            y: self.select_ext2(y_is_zero, &zero, &y3),
            is_infinity: BoolTarget::new_unsafe(self.select(y_is_zero, true_target, false_target)),
            _phantom: PhantomData,
        }
    }

    fn add_or_double_g2(&mut self, a: &G2AffineTarget<F, D>, b: &G2AffineTarget<F, D>) -> G2AffineTarget<F, D> {
        let a_is_inf = a.is_infinity;
        let b_is_inf = b.is_infinity;

        let x_equal = self.is_equal_ext2(&a.x, &b.x);

        let y_equal = self.is_equal_ext2(&a.y, &b.y);
        let should_double = self.and(x_equal, y_equal);

        let neg_b_y = self.neg_nonnative_ext2(&b.y);
        let y_opposite = self.is_equal_ext2(&a.y, &neg_b_y);
        let should_be_infinity_from_addition = self.and(x_equal, y_opposite);

        let doubled = self.double_g2(a);

        // Safe addition computation
        let v = self.sub_nonnative_ext2(&b.x, &a.x);
        let one = self.one_nonnative();
        let zero_nn = self.zero_nonnative();
        let one_ext2 = NonNativeTargetExt2 {
            c0: one,
            c1: zero_nn,
            _phantom: PhantomData,
        };
        let v_safe = self.select_ext2(x_equal, &one_ext2, &v);
        let v_inv = self.inv_nonnative_ext2(&v_safe);

        let u = self.sub_nonnative_ext2(&b.y, &a.y);
        let s = self.mul_nonnative_ext2(&u, &v_inv);
        let s_squared = self.squared_nonnative_ext2(&s);
        let x_sum = self.add_nonnative_ext2(&b.x, &a.x);
        let x3_add = self.sub_nonnative_ext2(&s_squared, &x_sum);
        let x_diff = self.sub_nonnative_ext2(&a.x, &x3_add);
        let prod = self.mul_nonnative_ext2(&s, &x_diff);
        let y3_add = self.sub_nonnative_ext2(&prod, &a.y);

        let zero = self.zero_nonnative_ext2();
        let infinity_point = G2AffineTarget {
            x: zero.clone(),
            y: zero.clone(),
            is_infinity: self._true(),
            _phantom: PhantomData,
        };

        let false_target = self._false().target;
        let result_if_not_special = G2AffineTarget {
            x: self.select_ext2(should_double, &doubled.x, &x3_add),
            y: self.select_ext2(should_double, &doubled.y, &y3_add),
            is_infinity: BoolTarget::new_unsafe(self.select(should_double, doubled.is_infinity.target, false_target)),
            _phantom: PhantomData,
        };

        let result_if_a_inf = b.clone();
        let result_if_b_inf = a.clone();
        let result_if_opposite = infinity_point;

        let mut result = result_if_not_special;
        result = self.select_g2(should_be_infinity_from_addition, &result_if_opposite, &result);
        result = self.select_g2(b_is_inf, &result_if_b_inf, &result);
        result = self.select_g2(a_is_inf, &result_if_a_inf, &result);

        result
    }

    fn neg_g2(&mut self, p: &G2AffineTarget<F, D>) -> G2AffineTarget<F, D> {
        G2AffineTarget {
            x: p.x.clone(),
            y: self.neg_nonnative_ext2(&p.y),
            is_infinity: p.is_infinity,
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::types::Field,
        iop::witness::PartialWitness,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };

    use super::*;
    use crate::crypto::bn254::field::extension::quadratic::QuadraticExtension;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_g2_basic() {
        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let point = G2Affine {
            x: QuadraticExtension([Bn128Base::ONE, Bn128Base::ZERO]),
            y: QuadraticExtension([Bn128Base::from_canonical_u64(2), Bn128Base::ZERO]),
            zero: false,
        };

        let g2_target = builder.constant_g2_affine(point);

        let same_point = builder.constant_g2_affine(point);
        let is_equal = builder.is_equal_g2(&g2_target, &same_point);
        builder.assert_one(is_equal.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_g2_selection() {
        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let point1 = G2Affine {
            x: QuadraticExtension([Bn128Base::ONE, Bn128Base::ZERO]),
            y: QuadraticExtension([Bn128Base::from_canonical_u64(2), Bn128Base::ZERO]),
            zero: false,
        };

        let point2 = G2Affine {
            x: QuadraticExtension([Bn128Base::from_canonical_u64(3), Bn128Base::ZERO]),
            y: QuadraticExtension([Bn128Base::from_canonical_u64(4), Bn128Base::ZERO]),
            zero: false,
        };

        let g2_target1 = builder.constant_g2_affine(point1);
        let g2_target2 = builder.constant_g2_affine(point2);

        let true_condition = builder._true();
        let selected = builder.select_g2(true_condition, &g2_target1, &g2_target2);

        let is_first = builder.is_equal_g2(&selected, &g2_target1);
        builder.assert_one(is_first.target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }
}
