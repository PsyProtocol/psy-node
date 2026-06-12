use std::marker::PhantomData;

use plonky2::{
    field::{
        extension::Extendable,
        types::{Field, PrimeField},
    },
    hash::hash_types::RichField,
    iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::crypto::bn254::{
    field::extension::quadratic::QuadraticExtension,
    gadgets::nonnative_fp::{CircuitBuilderNonNative, NonNativeTarget},
};

#[derive(Clone, Debug)]
pub struct NonNativeTargetExt2<FF: Field> {
    pub(crate) c0: NonNativeTarget<FF>,
    pub(crate) c1: NonNativeTarget<FF>,
    pub(crate) _phantom: PhantomData<FF>,
}

pub trait CircuitBuilderNonNativeExt2<F: RichField + Extendable<D>, const D: usize> {
    fn zero_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self) -> NonNativeTargetExt2<FF>;

    fn one_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self) -> NonNativeTargetExt2<FF>;

    fn constant_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: QuadraticExtension<FF>) -> NonNativeTargetExt2<FF>;

    fn connect_nonnative_ext2<FF: Field + Extendable<2>>(&mut self, lhs: &NonNativeTargetExt2<FF>, rhs: &NonNativeTargetExt2<FF>);

    fn add_virtual_nonnative_ext2_target<FF: Field + Extendable<2>>(&mut self) -> NonNativeTargetExt2<FF>;

    fn add_virtual_nonnative_target_ext2<FF: PrimeField + Extendable<2>>(&mut self) -> NonNativeTargetExt2<FF>;

    fn add_nonnative_ext2<FF: PrimeField + Extendable<2>>(
        &mut self,
        a: &NonNativeTargetExt2<FF>,
        b: &NonNativeTargetExt2<FF>,
    ) -> NonNativeTargetExt2<FF>;

    fn mul_nonnative_by_bool_ext2<FF: Field + Extendable<2>>(&mut self, a: &NonNativeTargetExt2<FF>, b: BoolTarget) -> NonNativeTargetExt2<FF>;

    fn sub_nonnative_ext2<FF: PrimeField + Extendable<2>>(
        &mut self,
        a: &NonNativeTargetExt2<FF>,
        b: &NonNativeTargetExt2<FF>,
    ) -> NonNativeTargetExt2<FF>;

    fn mul_nonnative_ext2<FF: PrimeField + Extendable<2>>(
        &mut self,
        a: &NonNativeTargetExt2<FF>,
        b: &NonNativeTargetExt2<FF>,
    ) -> NonNativeTargetExt2<FF>;

    fn neg_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: &NonNativeTargetExt2<FF>) -> NonNativeTargetExt2<FF>;

    fn inv_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: &NonNativeTargetExt2<FF>) -> NonNativeTargetExt2<FF>;

    fn mul_by_nonresidue_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: &NonNativeTargetExt2<FF>) -> NonNativeTargetExt2<FF>;

    fn nonnative_conditional_neg_ext2<FF: PrimeField + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt2<FF>,
        b: BoolTarget,
    ) -> NonNativeTargetExt2<FF>;

    fn squared_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: &NonNativeTargetExt2<FF>) -> NonNativeTargetExt2<FF>;

    fn scale_nonnative_ext2<FF: PrimeField + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt2<FF>,
        scalar: &NonNativeTarget<FF>,
    ) -> NonNativeTargetExt2<FF>;

    fn frobenius_map_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: &NonNativeTargetExt2<FF>, power: usize) -> NonNativeTargetExt2<FF>;

    fn is_equal_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: &NonNativeTargetExt2<FF>, y: &NonNativeTargetExt2<FF>) -> BoolTarget;

    fn select_ext2<FF: PrimeField + Extendable<2>>(
        &mut self,
        condition: BoolTarget,
        x: &NonNativeTargetExt2<FF>,
        y: &NonNativeTargetExt2<FF>,
    ) -> NonNativeTargetExt2<FF>;

    fn is_zero_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: &NonNativeTargetExt2<FF>) -> BoolTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderNonNativeExt2<F, D> for CircuitBuilder<F, D> {
    fn zero_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self) -> NonNativeTargetExt2<FF> {
        self.constant_nonnative_ext2(QuadraticExtension::ZERO)
    }

    fn one_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self) -> NonNativeTargetExt2<FF> {
        self.constant_nonnative_ext2(QuadraticExtension::ONE)
    }

    fn constant_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: QuadraticExtension<FF>) -> NonNativeTargetExt2<FF> {
        NonNativeTargetExt2 {
            c0: self.constant_nonnative(x.0[0]),
            c1: self.constant_nonnative(x.0[1]),
            _phantom: PhantomData,
        }
    }

    fn connect_nonnative_ext2<FF: Field + Extendable<2>>(&mut self, lhs: &NonNativeTargetExt2<FF>, rhs: &NonNativeTargetExt2<FF>) {
        self.connect_nonnative(&lhs.c0, &rhs.c0);
        self.connect_nonnative(&lhs.c1, &rhs.c1);
    }

    fn add_virtual_nonnative_ext2_target<FF: Field + Extendable<2>>(&mut self) -> NonNativeTargetExt2<FF> {
        let c0 = self.add_virtual_nonnative_target();
        let c1 = self.add_virtual_nonnative_target();
        NonNativeTargetExt2 {
            c0,
            c1,
            _phantom: PhantomData,
        }
    }

    fn add_nonnative_ext2<FF: PrimeField + Extendable<2>>(
        &mut self,
        a: &NonNativeTargetExt2<FF>,
        b: &NonNativeTargetExt2<FF>,
    ) -> NonNativeTargetExt2<FF> {
        let c0 = self.add_nonnative(&a.c0, &b.c0);
        let c1 = self.add_nonnative(&a.c1, &b.c1);
        NonNativeTargetExt2 {
            c0,
            c1,
            _phantom: PhantomData,
        }
    }

    fn mul_nonnative_by_bool_ext2<FF: Field + Extendable<2>>(&mut self, a: &NonNativeTargetExt2<FF>, b: BoolTarget) -> NonNativeTargetExt2<FF> {
        let c0 = self.mul_nonnative_by_bool(&a.c0, b);
        let c1 = self.mul_nonnative_by_bool(&a.c1, b);
        NonNativeTargetExt2 {
            c0,
            c1,
            _phantom: PhantomData,
        }
    }

    fn sub_nonnative_ext2<FF: PrimeField + Extendable<2>>(
        &mut self,
        a: &NonNativeTargetExt2<FF>,
        b: &NonNativeTargetExt2<FF>,
    ) -> NonNativeTargetExt2<FF> {
        let c0 = self.sub_nonnative(&a.c0, &b.c0);
        let c1 = self.sub_nonnative(&a.c1, &b.c1);
        NonNativeTargetExt2 {
            c0,
            c1,
            _phantom: PhantomData,
        }
    }

    fn mul_nonnative_ext2<FF: PrimeField + Extendable<2>>(
        &mut self,
        a: &NonNativeTargetExt2<FF>,
        b: &NonNativeTargetExt2<FF>,
    ) -> NonNativeTargetExt2<FF> {
        let aa = self.mul_nonnative(&a.c0, &b.c0);
        let bb = self.mul_nonnative(&a.c1, &b.c1);
        let aa_add_bb = self.add_nonnative(&aa, &bb);
        let bb_mul_nonresidue = self.mul_by_nonresidue_nonnative(&bb);
        let a0_add_a1 = self.add_nonnative(&a.c0, &a.c1);
        let b0_add_b1 = self.add_nonnative(&b.c0, &b.c1);
        let t = self.mul_nonnative(&a0_add_a1, &b0_add_b1);

        NonNativeTargetExt2 {
            c0: self.add_nonnative(&bb_mul_nonresidue, &aa),
            c1: self.sub_nonnative(&t, &aa_add_bb),
            _phantom: PhantomData,
        }
    }

    fn neg_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: &NonNativeTargetExt2<FF>) -> NonNativeTargetExt2<FF> {
        NonNativeTargetExt2 {
            c0: self.neg_nonnative(&x.c0),
            c1: self.neg_nonnative(&x.c1),
            _phantom: PhantomData,
        }
    }

    fn inv_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: &NonNativeTargetExt2<FF>) -> NonNativeTargetExt2<FF> {
        let c0_squared = self.mul_nonnative(&x.c0, &x.c0);
        let c1_squared = self.mul_nonnative(&x.c1, &x.c1);
        let c1_squared_mul_nonresidue = self.mul_by_nonresidue_nonnative(&c1_squared);
        let t = self.sub_nonnative(&c0_squared, &c1_squared_mul_nonresidue);
        let inv_t = self.inv_nonnative(&t);
        let c1_mul_inv_t = self.mul_nonnative(&x.c1, &inv_t);

        NonNativeTargetExt2 {
            c0: self.mul_nonnative(&x.c0, &inv_t),
            c1: self.neg_nonnative(&c1_mul_inv_t),
            _phantom: PhantomData,
        }
    }

    fn mul_by_nonresidue_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: &NonNativeTargetExt2<FF>) -> NonNativeTargetExt2<FF> {
        // Check if FF is Bn128Base
        use core::any::TypeId;

        use crate::crypto::bn254::field::{bn128_base::Bn128Base, bn128_extension::Bn128ExtConstants};

        if TypeId::of::<FF>() == TypeId::of::<Bn128Base>() {
            // For Bn128Base, use EXT_NONRESIDUE = [9, 1]
            let ext_nonresidue = <Bn128Base as Bn128ExtConstants>::EXT_NONRESIDUE;
            let nonresidue = unsafe {
                let transmuted: QuadraticExtension<FF> = core::mem::transmute_copy(&QuadraticExtension(ext_nonresidue));
                self.constant_nonnative_ext2(transmuted)
            };
            self.mul_nonnative_ext2(&x, &nonresidue)
        } else {
            // Generic implementation: multiply c1 by W and swap
            let w = self.constant_nonnative(FF::W);
            let c0 = self.mul_nonnative(&x.c1, &w);
            NonNativeTargetExt2 {
                c0,
                c1: x.c0.clone(),
                _phantom: PhantomData,
            }
        }
    }

    fn nonnative_conditional_neg_ext2<FF: PrimeField + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt2<FF>,
        b: BoolTarget,
    ) -> NonNativeTargetExt2<FF> {
        let c0 = self.nonnative_conditional_neg(&x.c0, b);
        let c1 = self.nonnative_conditional_neg(&x.c1, b);
        NonNativeTargetExt2 {
            c0,
            c1,
            _phantom: PhantomData,
        }
    }

    fn squared_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: &NonNativeTargetExt2<FF>) -> NonNativeTargetExt2<FF> {
        let ab = self.mul_nonnative(&x.c0, &x.c1);
        let c1 = self.add_nonnative(&ab, &ab);
        let a_add_b = self.add_nonnative(&x.c0, &x.c1);
        let b_mul_nonresidue = self.mul_by_nonresidue_nonnative(&x.c1);
        let a_add_b_mul_nonresidue = self.add_nonnative(&x.c0, &b_mul_nonresidue);
        let a_add_b_mul_nonresidue_mul_a_add_b = self.mul_nonnative(&a_add_b, &a_add_b_mul_nonresidue);
        let ab_mul_nonresidue = self.mul_by_nonresidue_nonnative(&ab);
        let mut c0 = self.sub_nonnative(&a_add_b_mul_nonresidue_mul_a_add_b, &ab);
        c0 = self.sub_nonnative(&c0, &ab_mul_nonresidue);
        NonNativeTargetExt2 {
            c0,
            c1,
            _phantom: PhantomData,
        }
    }

    fn scale_nonnative_ext2<FF: PrimeField + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt2<FF>,
        scalar: &NonNativeTarget<FF>,
    ) -> NonNativeTargetExt2<FF> {
        let c0 = self.mul_nonnative(&x.c0, scalar);
        let c1 = self.mul_nonnative(&x.c1, scalar);
        NonNativeTargetExt2 {
            c0,
            c1,
            _phantom: PhantomData,
        }
    }

    fn frobenius_map_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: &NonNativeTargetExt2<FF>, power: usize) -> NonNativeTargetExt2<FF> {
        if power % 2 == 0 {
            x.clone()
        } else {
            NonNativeTargetExt2 {
                c0: x.c0.clone(),
                c1: self.mul_by_nonresidue_nonnative(&x.c1),
                _phantom: PhantomData,
            }
        }
    }

    fn is_equal_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: &NonNativeTargetExt2<FF>, y: &NonNativeTargetExt2<FF>) -> BoolTarget {
        let c0_equal = self.is_equal_nonnative(&x.c0, &y.c0);
        let c1_equal = self.is_equal_nonnative(&x.c1, &y.c1);
        self.and(c0_equal, c1_equal)
    }

    fn select_ext2<FF: PrimeField + Extendable<2>>(
        &mut self,
        condition: BoolTarget,
        x: &NonNativeTargetExt2<FF>,
        y: &NonNativeTargetExt2<FF>,
    ) -> NonNativeTargetExt2<FF> {
        NonNativeTargetExt2 {
            c0: self.select_nonnative(condition, &x.c0, &y.c0),
            c1: self.select_nonnative(condition, &x.c1, &y.c1),
            _phantom: PhantomData,
        }
    }

    fn is_zero_nonnative_ext2<FF: PrimeField + Extendable<2>>(&mut self, x: &NonNativeTargetExt2<FF>) -> BoolTarget {
        let c0_is_zero = self.is_zero_nonnative(&x.c0);
        let c1_is_zero = self.is_zero_nonnative(&x.c1);
        self.and(c0_is_zero, c1_is_zero)
    }

    fn add_virtual_nonnative_target_ext2<FF: PrimeField + Extendable<2>>(&mut self) -> NonNativeTargetExt2<FF> {
        NonNativeTargetExt2 {
            c0: self.add_virtual_nonnative_target(),
            c1: self.add_virtual_nonnative_target(),
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::types::Field,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use super::*;
    use crate::crypto::bn254::field::{bn128_base::Bn128Base, extension::quadratic::QuadraticExtension};

    #[test]
    fn test_nonnative_ext2_add() -> anyhow::Result<()> {
        type FF = QuadraticExtension<Bn128Base>;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let x_ff = FF::rand();
        let y_ff = FF::rand();
        let sum_ff = x_ff + y_ff;

        let config = crate::crypto::bn254::pairing_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative_ext2(x_ff);
        let y = builder.constant_nonnative_ext2(y_ff);
        let sum = builder.add_nonnative_ext2(&x, &y);

        let sum_expected = builder.constant_nonnative_ext2(sum_ff);
        builder.connect_nonnative_ext2(&sum, &sum_expected);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_nonnative_ext2_sub() -> anyhow::Result<()> {
        type FF = QuadraticExtension<Bn128Base>;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let x_ff = FF::rand();
        let y_ff = FF::rand();
        let _diff_ff = x_ff - y_ff;

        let config = crate::crypto::bn254::pairing_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative_ext2(x_ff);
        let y = builder.constant_nonnative_ext2(y_ff);
        let diff = builder.sub_nonnative_ext2(&x, &y);

        let sum = builder.add_nonnative_ext2(&diff, &y);
        builder.connect_nonnative_ext2(&sum, &x);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_nonnative_ext2_mul() -> anyhow::Result<()> {
        type FF = QuadraticExtension<Bn128Base>;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let x_ff = FF::rand();
        let y_ff = FF::rand();
        let _product_ff = x_ff * y_ff;

        let config = crate::crypto::bn254::pairing_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative_ext2(x_ff);
        let y = builder.constant_nonnative_ext2(y_ff);
        let _product = builder.mul_nonnative_ext2(&x, &y);

        let one = builder.constant_nonnative_ext2(FF::ONE);
        let x_times_one = builder.mul_nonnative_ext2(&x, &one);
        builder.connect_nonnative_ext2(&x_times_one, &x);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_nonnative_ext2_neg() -> anyhow::Result<()> {
        type FF = QuadraticExtension<Bn128Base>;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let x_ff = FF::rand();
        let neg_x_ff = -x_ff;

        let config = crate::crypto::bn254::pairing_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative_ext2(x_ff);
        let neg_x = builder.neg_nonnative_ext2(&x);

        let neg_x_expected = builder.constant_nonnative_ext2(neg_x_ff);
        builder.connect_nonnative_ext2(&neg_x, &neg_x_expected);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_nonnative_ext2_inv() -> anyhow::Result<()> {
        type FF = QuadraticExtension<Bn128Base>;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let x_ff = FF::rand();
        let inv_x_ff = x_ff.inverse();

        let config = crate::crypto::bn254::pairing_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative_ext2(x_ff);
        let inv_x = builder.inv_nonnative_ext2(&x);

        let inv_x_expected = builder.constant_nonnative_ext2(inv_x_ff);
        builder.connect_nonnative_ext2(&inv_x, &inv_x_expected);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_nonnative_ext2_square() -> anyhow::Result<()> {
        type FF = QuadraticExtension<Bn128Base>;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let x_ff = FF::rand();
        let square_x_ff = x_ff.square();

        let config = crate::crypto::bn254::pairing_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative_ext2(x_ff);
        let square_x = builder.squared_nonnative_ext2(&x);
        let square_x_expected = builder.constant_nonnative_ext2(square_x_ff);
        builder.connect_nonnative_ext2(&square_x, &square_x_expected);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_nonnative_ext2_mul_by_nonresidue() -> anyhow::Result<()> {
        use crate::crypto::bn254::field::bn128_extension::Bn128ExtConstants;

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        // Test with a specific value to verify correctness
        let x_ff = QuadraticExtension([Bn128Base::from_canonical_u64(2), Bn128Base::from_canonical_u64(3)]);

        // Expected result: (2 + 3u) * (9 + u) = 18 + 2u + 27u + 3u^2
        // Since u^2 = -1, this becomes: 18 + 29u - 3 = 15 + 29u
        let ext_nonresidue = <Bn128Base as Bn128ExtConstants>::EXT_NONRESIDUE;
        let nonresidue = QuadraticExtension(ext_nonresidue);
        let expected_ff = x_ff * nonresidue;

        // Print values to verify
        println!("Testing mul_by_nonresidue for Bn128Base");
        println!("x = {:?}", x_ff);
        println!("nonresidue = {:?}", nonresidue);
        println!("x * nonresidue = {:?}", expected_ff);

        let config = crate::crypto::bn254::pairing_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative_ext2(x_ff);
        let result = builder.mul_by_nonresidue_nonnative_ext2(&x);
        let expected = builder.constant_nonnative_ext2(expected_ff);

        builder.connect_nonnative_ext2(&result, &expected);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_nonnative_ext2_inv_with_verification() -> anyhow::Result<()> {
        type FF = QuadraticExtension<Bn128Base>;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        // Test with specific values to verify correctness
        let x_ff = QuadraticExtension([Bn128Base::from_canonical_u64(7), Bn128Base::from_canonical_u64(5)]);

        let inv_x_ff = x_ff.inverse();

        // Verify that x * inv(x) = 1
        let product = x_ff * inv_x_ff;
        println!("Testing inv for Fp2");
        println!("x = {:?}", x_ff);
        println!("inv(x) = {:?}", inv_x_ff);
        println!("x * inv(x) = {:?}", product);
        assert_eq!(product, FF::ONE, "x * inv(x) should equal 1");

        let config = crate::crypto::bn254::pairing_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative_ext2(x_ff);
        let inv_x = builder.inv_nonnative_ext2(&x);

        // Verify inv(x) is correct
        let inv_x_expected = builder.constant_nonnative_ext2(inv_x_ff);
        builder.connect_nonnative_ext2(&inv_x, &inv_x_expected);

        // Also verify that x * inv(x) = 1
        let product = builder.mul_nonnative_ext2(&x, &inv_x);
        let one = builder.one_nonnative_ext2();
        builder.connect_nonnative_ext2(&product, &one);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }
}
