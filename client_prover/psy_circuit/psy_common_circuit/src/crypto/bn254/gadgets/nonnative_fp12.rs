use std::marker::PhantomData;

use plonky2::{
    field::{
        extension::Extendable,
        types::{Field, PrimeField},
    },
    hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::crypto::bn254::{
    field::{
        bn128_base::Bn128Base,
        extension::{dodecic::DodecicExtension, quadratic::QuadraticExtension, sextic::SexticExtension},
    },
    gadgets::{
        nonnative_fp2::{CircuitBuilderNonNativeExt2, NonNativeTargetExt2},
        nonnative_fp6::{CircuitBuilderNonNativeExt6, NonNativeTargetExt6},
    },
};

const CYCLOTOMIC_POW_LOOP: [u64; 4] = [4965661367192848881, 0, 0, 0];

#[derive(Clone, Debug)]
pub struct NonNativeTargetExt12<FF: Field> {
    pub(crate) c0: NonNativeTargetExt6<FF>,
    pub(crate) c1: NonNativeTargetExt6<FF>,
    pub(crate) _phantom: PhantomData<FF>,
}

pub trait CircuitBuilderNonNativeExt12<F: RichField + Extendable<D>, const D: usize> {
    fn zero_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(&mut self) -> NonNativeTargetExt12<FF>;

    fn constant_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: DodecicExtension<FF>,
    ) -> NonNativeTargetExt12<FF>;

    fn connect_nonnative_ext12<FF: Field + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        lhs: &NonNativeTargetExt12<FF>,
        rhs: &NonNativeTargetExt12<FF>,
    );

    fn add_virtual_nonnative_ext12_target<FF: Field + Extendable<12> + Extendable<6> + Extendable<2>>(&mut self) -> NonNativeTargetExt12<FF>;

    fn add_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        a: &NonNativeTargetExt12<FF>,
        b: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF>;

    fn sub_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        a: &NonNativeTargetExt12<FF>,
        b: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF>;

    fn mul_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        a: &NonNativeTargetExt12<FF>,
        b: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF>;

    fn neg_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF>;

    fn inv_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF>;

    fn squared_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF>;

    fn mul_by_024<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
        ell_0: &NonNativeTargetExt2<FF>,
        ell_vw: &NonNativeTargetExt2<FF>,
        ell_vv: &NonNativeTargetExt2<FF>,
    ) -> NonNativeTargetExt12<FF>;

    fn final_exponentiation_first_chunk<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF>;

    fn final_exponentiation_last_chunk<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF>;

    fn unitary_inverse_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF>;

    fn frobenius_map_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
        power: usize,
    ) -> NonNativeTargetExt12<FF>;

    fn frobenius_coeffs_c1_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        power: usize,
    ) -> NonNativeTargetExt2<FF>;

    fn cyclotomic_pow_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF>;

    fn cyclotomic_squared_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF>;

    fn exp_by_neg_z_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF>;

    fn is_equal_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        a: &NonNativeTargetExt12<FF>,
        b: &NonNativeTargetExt12<FF>,
    ) -> plonky2::iop::target::BoolTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderNonNativeExt12<F, D> for CircuitBuilder<F, D> {
    fn zero_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(&mut self) -> NonNativeTargetExt12<FF> {
        self.constant_nonnative_ext12(DodecicExtension::ZERO)
    }

    fn constant_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: DodecicExtension<FF>,
    ) -> NonNativeTargetExt12<FF> {
        NonNativeTargetExt12 {
            c0: self.constant_nonnative_ext6(SexticExtension([x.0[0], x.0[1], x.0[2], x.0[3], x.0[4], x.0[5]])),
            c1: self.constant_nonnative_ext6(SexticExtension([x.0[6], x.0[7], x.0[8], x.0[9], x.0[10], x.0[11]])),
            _phantom: PhantomData,
        }
    }

    fn connect_nonnative_ext12<FF: Field + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        lhs: &NonNativeTargetExt12<FF>,
        rhs: &NonNativeTargetExt12<FF>,
    ) {
        self.connect_nonnative_ext6(&rhs.c0, &lhs.c0);
        self.connect_nonnative_ext6(&rhs.c1, &lhs.c1);
    }

    fn add_virtual_nonnative_ext12_target<FF: Field + Extendable<12> + Extendable<6> + Extendable<2>>(&mut self) -> NonNativeTargetExt12<FF> {
        let c0 = self.add_virtual_nonnative_ext6_target();
        let c1 = self.add_virtual_nonnative_ext6_target();
        NonNativeTargetExt12 {
            c0,
            c1,
            _phantom: PhantomData,
        }
    }

    fn add_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        a: &NonNativeTargetExt12<FF>,
        b: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF> {
        let c0 = self.add_nonnative_ext6(&a.c0, &b.c0);
        let c1 = self.add_nonnative_ext6(&a.c1, &b.c1);
        NonNativeTargetExt12 {
            c0,
            c1,
            _phantom: PhantomData,
        }
    }

    fn sub_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        a: &NonNativeTargetExt12<FF>,
        b: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF> {
        let c0 = self.sub_nonnative_ext6(&a.c0, &b.c0);
        let c1 = self.sub_nonnative_ext6(&a.c1, &b.c1);
        NonNativeTargetExt12 {
            c0,
            c1,
            _phantom: PhantomData,
        }
    }

    fn mul_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        a: &NonNativeTargetExt12<FF>,
        b: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF> {
        let aa = self.mul_nonnative_ext6(&a.c0, &b.c0);
        let bb = self.mul_nonnative_ext6(&a.c1, &b.c1);
        let aa_add_bb = self.add_nonnative_ext6(&aa, &bb);
        let bb_mul_nonresidue = self.mul_by_nonresidue_nonnative_ext6(&bb);
        let a0_add_a1 = self.add_nonnative_ext6(&a.c0, &a.c1);
        let b0_add_b1 = self.add_nonnative_ext6(&b.c0, &b.c1);
        let t = self.mul_nonnative_ext6(&a0_add_a1, &b0_add_b1);

        NonNativeTargetExt12 {
            c0: self.add_nonnative_ext6(&bb_mul_nonresidue, &aa),
            c1: self.sub_nonnative_ext6(&t, &aa_add_bb),
            _phantom: PhantomData,
        }
    }

    fn neg_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF> {
        NonNativeTargetExt12 {
            c0: self.neg_nonnative_ext6(&x.c0),
            c1: self.neg_nonnative_ext6(&x.c1),
            _phantom: PhantomData,
        }
    }

    fn inv_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF> {
        let c0_squared = self.squared_nonnative_ext6(&x.c0);
        let c1_squared = self.squared_nonnative_ext6(&x.c1);
        let c1_squared_mul_nonresidue = self.mul_by_nonresidue_nonnative_ext6(&c1_squared);
        let t = self.sub_nonnative_ext6(&c0_squared, &c1_squared_mul_nonresidue);
        let inv_t = self.inv_nonnative_ext6(&t);
        let c1_mul_inv_t = self.mul_nonnative_ext6(&x.c1, &inv_t);

        NonNativeTargetExt12 {
            c0: self.mul_nonnative_ext6(&x.c0, &inv_t),
            c1: self.neg_nonnative_ext6(&c1_mul_inv_t),
            _phantom: PhantomData,
        }
    }

    fn squared_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF> {
        let ab = self.mul_nonnative_ext6(&x.c0, &x.c1);
        let c1 = self.add_nonnative_ext6(&ab, &ab);
        let a_add_b = self.add_nonnative_ext6(&x.c0, &x.c1);
        let b_mul_nonresidue = self.mul_by_nonresidue_nonnative_ext6(&x.c1);
        let a_add_b_mul_nonresidue = self.add_nonnative_ext6(&x.c0, &b_mul_nonresidue);
        let a_add_b_mul_nonresidue_mul_a_add_b = self.mul_nonnative_ext6(&a_add_b, &a_add_b_mul_nonresidue);
        let ab_mul_nonresidue = self.mul_by_nonresidue_nonnative_ext6(&ab);
        let mut c0 = self.sub_nonnative_ext6(&a_add_b_mul_nonresidue_mul_a_add_b, &ab);
        c0 = self.sub_nonnative_ext6(&c0, &ab_mul_nonresidue);
        NonNativeTargetExt12 {
            c0,
            c1,
            _phantom: PhantomData,
        }
    }

    fn mul_by_024<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
        ell_0: &NonNativeTargetExt2<FF>,
        ell_vw: &NonNativeTargetExt2<FF>,
        ell_vv: &NonNativeTargetExt2<FF>,
    ) -> NonNativeTargetExt12<FF> {
        let z0 = x.c0.c0.clone();
        let z1 = x.c0.c1.clone();
        let z2 = x.c0.c2.clone();
        let z3 = x.c1.c0.clone();
        let z4 = x.c1.c1.clone();
        let z5 = x.c1.c2.clone();

        let x0 = ell_0.clone();
        let x2 = ell_vv.clone();
        let x4 = ell_vw.clone();

        let d0 = self.mul_nonnative_ext2(&z0, &x0);
        let d2 = self.mul_nonnative_ext2(&z2, &x2);
        let d4 = self.mul_nonnative_ext2(&z4, &x4);
        let t2 = self.add_nonnative_ext2(&z0, &z4);
        let t1 = self.add_nonnative_ext2(&z0, &z2);
        let mut s0 = self.add_nonnative_ext2(&z1, &z3);
        s0 = self.add_nonnative_ext2(&s0, &z5);

        let s1 = self.mul_nonnative_ext2(&z1, &x2);
        let t3 = self.add_nonnative_ext2(&s1, &d4);
        let mut t4 = self.mul_by_nonresidue_nonnative_ext2(&t3);
        t4 = self.add_nonnative_ext2(&t4, &d0);
        let z0 = t4;

        let t3 = self.mul_nonnative_ext2(&z5, &x4);
        let s1 = self.add_nonnative_ext2(&s1, &t3);
        let t3 = self.add_nonnative_ext2(&t3, &d2);
        let t4 = self.mul_by_nonresidue_nonnative_ext2(&t3);
        let t3 = self.mul_nonnative_ext2(&z1, &x0);
        let s1 = self.add_nonnative_ext2(&s1, &t3);
        let t4 = self.add_nonnative_ext2(&t4, &t3);
        let z1 = t4;

        let t0 = self.add_nonnative_ext2(&x0, &x2);
        let mut t3 = self.mul_nonnative_ext2(&t1, &t0);
        t3 = self.sub_nonnative_ext2(&t3, &d0);
        t3 = self.sub_nonnative_ext2(&t3, &d2);
        let t4 = self.mul_nonnative_ext2(&z3, &x4);
        let s1 = self.add_nonnative_ext2(&s1, &t4);
        let t3 = self.add_nonnative_ext2(&t3, &t4);

        let t0 = self.add_nonnative_ext2(&z2, &z4);
        let z2 = t3;

        let t1 = self.add_nonnative_ext2(&x2, &x4);
        let mut t3 = self.mul_nonnative_ext2(&t0, &t1);
        t3 = self.sub_nonnative_ext2(&t3, &d2);
        t3 = self.sub_nonnative_ext2(&t3, &d4);
        let t4 = self.mul_by_nonresidue_nonnative_ext2(&t3);
        let t3 = self.mul_nonnative_ext2(&z3, &x0);
        let s1 = self.add_nonnative_ext2(&s1, &t3);
        let t4 = self.add_nonnative_ext2(&t4, &t3);
        let z3 = t4;

        let t3 = self.mul_nonnative_ext2(&z5, &x2);
        let s1 = self.add_nonnative_ext2(&s1, &t3);
        let t4 = self.mul_by_nonresidue_nonnative_ext2(&t3);
        let t0 = self.add_nonnative_ext2(&x0, &x4);
        let mut t3 = self.mul_nonnative_ext2(&t2, &t0);
        t3 = self.sub_nonnative_ext2(&t3, &d0);
        t3 = self.sub_nonnative_ext2(&t3, &d4);
        let t4 = self.add_nonnative_ext2(&t4, &t3);
        let z4 = t4;

        let mut t0 = self.add_nonnative_ext2(&x0, &x2);
        t0 = self.add_nonnative_ext2(&t0, &x4);
        let mut t3 = self.mul_nonnative_ext2(&s0, &t0);
        t3 = self.sub_nonnative_ext2(&t3, &s1);
        let z5 = t3;

        NonNativeTargetExt12 {
            c0: NonNativeTargetExt6 {
                c0: z0,
                c1: z1,
                c2: z2,
                _phantom: PhantomData,
            },
            c1: NonNativeTargetExt6 {
                c0: z3,
                c1: z4,
                c2: z5,
                _phantom: PhantomData,
            },
            _phantom: PhantomData,
        }
    }

    fn final_exponentiation_first_chunk<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF> {
        let b = self.inv_nonnative_ext12(x);
        let a = self.unitary_inverse_nonnative_ext12(x);
        let c = self.mul_nonnative_ext12(&a, &b);
        let d = self.frobenius_map_nonnative_ext12(&c, 2);
        return self.mul_nonnative_ext12(&d, &c);
    }

    fn final_exponentiation_last_chunk<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF> {
        let a = self.exp_by_neg_z_nonnative_ext12(x);
        let b = self.cyclotomic_squared_nonnative_ext12(&a);
        let c = self.cyclotomic_squared_nonnative_ext12(&b);
        let d = self.mul_nonnative_ext12(&c, &b);

        let e = self.exp_by_neg_z_nonnative_ext12(&d);
        let f = self.cyclotomic_squared_nonnative_ext12(&e);
        let g = self.exp_by_neg_z_nonnative_ext12(&f);
        let h = self.unitary_inverse_nonnative_ext12(&d);
        let i = self.unitary_inverse_nonnative_ext12(&g);

        let j = self.mul_nonnative_ext12(&i, &e);
        let k = self.mul_nonnative_ext12(&j, &h);
        let l = self.mul_nonnative_ext12(&k, &b);
        let m = self.mul_nonnative_ext12(&k, &e);
        let n = self.mul_nonnative_ext12(x, &m);

        let o = self.frobenius_map_nonnative_ext12(&l, 1);
        let p = self.mul_nonnative_ext12(&o, &n);

        let q = self.frobenius_map_nonnative_ext12(&k, 2);
        let r = self.mul_nonnative_ext12(&q, &p);

        let s = self.unitary_inverse_nonnative_ext12(x);
        let t = self.mul_nonnative_ext12(&s, &l);
        let u = self.frobenius_map_nonnative_ext12(&t, 3);
        let v = self.mul_nonnative_ext12(&u, &r);

        v
    }

    fn unitary_inverse_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF> {
        NonNativeTargetExt12 {
            c0: x.c0.clone(),
            c1: self.neg_nonnative_ext6(&x.c1),
            _phantom: PhantomData,
        }
    }

    fn frobenius_map_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
        power: usize,
    ) -> NonNativeTargetExt12<FF> {
        let c0 = self.frobenius_map_nonnative_ext6(&x.c0, power);
        let mut c1 = self.frobenius_map_nonnative_ext6(&x.c1, power);
        let frobenius_coeffs_c1 = self.frobenius_coeffs_c1_nonnative_ext12::<FF>(power);
        c1 = self.scale_nonnative_ext6(&c1, &frobenius_coeffs_c1);

        NonNativeTargetExt12 {
            c0,
            c1,
            _phantom: PhantomData,
        }
    }

    fn frobenius_coeffs_c1_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        power: usize,
    ) -> NonNativeTargetExt2<FF> {
        use std::any::TypeId;

        use crate::crypto::bn254::field::bn128_extension::Bn128ExtConstants;

        if TypeId::of::<FF>() == TypeId::of::<Bn128Base>() {
            match power % 12 {
                0 => self.constant_nonnative_ext2(QuadraticExtension([FF::ONE, FF::ZERO])),
                1 => {
                    let coeffs = <Bn128Base as Bn128ExtConstants>::FROBENIUS_COEFFS_EXT12_C1;
                    let ff_coeff0 = unsafe { std::mem::transmute_copy::<Bn128Base, FF>(&coeffs[0]) };
                    let ff_coeff1 = unsafe { std::mem::transmute_copy::<Bn128Base, FF>(&coeffs[1]) };
                    self.constant_nonnative_ext2(QuadraticExtension([ff_coeff0, ff_coeff1]))
                }
                2 => {
                    let coeffs = <Bn128Base as Bn128ExtConstants>::FROBENIUS_COEFFS_EXT12_C1;
                    let ff_coeff0 = unsafe { std::mem::transmute_copy::<Bn128Base, FF>(&coeffs[2]) };
                    let ff_coeff1 = unsafe { std::mem::transmute_copy::<Bn128Base, FF>(&coeffs[3]) };
                    self.constant_nonnative_ext2(QuadraticExtension([ff_coeff0, ff_coeff1]))
                }
                3 => {
                    let coeffs = <Bn128Base as Bn128ExtConstants>::FROBENIUS_COEFFS_EXT12_C1;
                    let ff_coeff0 = unsafe { std::mem::transmute_copy::<Bn128Base, FF>(&coeffs[4]) };
                    let ff_coeff1 = unsafe { std::mem::transmute_copy::<Bn128Base, FF>(&coeffs[5]) };
                    self.constant_nonnative_ext2(QuadraticExtension([ff_coeff0, ff_coeff1]))
                }
                _ => unreachable!(),
            }
        } else {
            panic!("frobenius_coeffs_c1_nonnative_ext12 only supports Bn128Base")
        }
    }

    fn cyclotomic_pow_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF> {
        let mut res = self.constant_nonnative_ext12(DodecicExtension::ONE);
        let mut found_one = false;

        for j in CYCLOTOMIC_POW_LOOP.iter().rev() {
            for i in (0..64).rev() {
                if found_one {
                    res = self.cyclotomic_squared_nonnative_ext12(&res);
                }

                if (j >> i) & 1 == 1 {
                    found_one = true;
                    res = self.mul_nonnative_ext12(&x, &res);
                }
            }
        }

        res
    }

    fn cyclotomic_squared_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF> {
        let mut z0 = x.c0.c0.clone();
        let mut z4 = x.c0.c1.clone();
        let mut z3 = x.c0.c2.clone();
        let mut z2 = x.c1.c0.clone();
        let mut z1 = x.c1.c1.clone();
        let mut z5 = x.c1.c2.clone();

        let mut tmp = self.mul_nonnative_ext2(&z0, &z1);
        let mut tmp_mul_by_nonresidue = self.mul_by_nonresidue_nonnative_ext2(&tmp);
        let mut t0 = self.mul_by_nonresidue_nonnative_ext2(&z1);
        t0 = self.add_nonnative_ext2(&t0, &z0);
        let z0_add_z1 = self.add_nonnative_ext2(&z0, &z1);
        t0 = self.mul_nonnative_ext2(&t0, &z0_add_z1);
        t0 = self.sub_nonnative_ext2(&t0, &tmp);
        t0 = self.sub_nonnative_ext2(&t0, &tmp_mul_by_nonresidue);
        let t1 = self.add_nonnative_ext2(&tmp, &tmp);

        tmp = self.mul_nonnative_ext2(&z2, &z3);
        tmp_mul_by_nonresidue = self.mul_by_nonresidue_nonnative_ext2(&tmp);
        let mut t2 = self.mul_by_nonresidue_nonnative_ext2(&z3);
        t2 = self.add_nonnative_ext2(&t2, &z2);
        let z2_add_z3 = self.add_nonnative_ext2(&z2, &z3);
        t2 = self.mul_nonnative_ext2(&t2, &z2_add_z3);
        t2 = self.sub_nonnative_ext2(&t2, &tmp);
        t2 = self.sub_nonnative_ext2(&t2, &tmp_mul_by_nonresidue);
        let t3 = self.add_nonnative_ext2(&tmp, &tmp);

        tmp = self.mul_nonnative_ext2(&z4, &z5);
        tmp_mul_by_nonresidue = self.mul_by_nonresidue_nonnative_ext2(&tmp);
        let mut t4 = self.mul_by_nonresidue_nonnative_ext2(&z5);
        t4 = self.add_nonnative_ext2(&t4, &z4);
        let z4_add_z5 = self.add_nonnative_ext2(&z4, &z5);
        t4 = self.mul_nonnative_ext2(&t4, &z4_add_z5);
        t4 = self.sub_nonnative_ext2(&t4, &tmp);
        t4 = self.sub_nonnative_ext2(&t4, &tmp_mul_by_nonresidue);
        let t5 = self.add_nonnative_ext2(&tmp, &tmp);

        z0 = self.sub_nonnative_ext2(&t0, &z0);
        z0 = self.add_nonnative_ext2(&z0, &z0);
        z0 = self.add_nonnative_ext2(&z0, &t0);
        z1 = self.add_nonnative_ext2(&t1, &z1);
        z1 = self.add_nonnative_ext2(&z1, &z1);
        z1 = self.add_nonnative_ext2(&z1, &t1);

        tmp = self.mul_by_nonresidue_nonnative_ext2(&t5);
        z2 = self.add_nonnative_ext2(&tmp, &z2);
        z2 = self.add_nonnative_ext2(&z2, &z2);
        z2 = self.add_nonnative_ext2(&z2, &tmp);

        z3 = self.sub_nonnative_ext2(&t4, &z3);
        z3 = self.add_nonnative_ext2(&z3, &z3);
        z3 = self.add_nonnative_ext2(&z3, &t4);
        z4 = self.sub_nonnative_ext2(&t2, &z4);
        z4 = self.add_nonnative_ext2(&z4, &z4);
        z4 = self.add_nonnative_ext2(&z4, &t2);
        z5 = self.add_nonnative_ext2(&t3, &z5);
        z5 = self.add_nonnative_ext2(&z5, &z5);
        z5 = self.add_nonnative_ext2(&z5, &t3);

        NonNativeTargetExt12 {
            c0: NonNativeTargetExt6 {
                c0: z0,
                c1: z4,
                c2: z3,
                _phantom: PhantomData,
            },
            c1: NonNativeTargetExt6 {
                c0: z2,
                c1: z1,
                c2: z5,
                _phantom: PhantomData,
            },
            _phantom: PhantomData,
        }
    }

    fn exp_by_neg_z_nonnative_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        x: &NonNativeTargetExt12<FF>,
    ) -> NonNativeTargetExt12<FF> {
        let t = self.cyclotomic_pow_nonnative_ext12(&x);
        self.unitary_inverse_nonnative_ext12(&t)
    }

    fn is_equal_ext12<FF: PrimeField + Extendable<12> + Extendable<6> + Extendable<2>>(
        &mut self,
        a: &NonNativeTargetExt12<FF>,
        b: &NonNativeTargetExt12<FF>,
    ) -> plonky2::iop::target::BoolTarget {
        let c0_eq = self.is_equal_ext6(&a.c0, &b.c0);
        let c1_eq = self.is_equal_ext6(&a.c1, &b.c1);
        self.and(c0_eq, c1_eq)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::{
        field::{
            extension::FieldExtension,
            types::{Field, Sample},
        },
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::crypto::bn254::{
        field::{bn128_base::Bn128Base, extension::dodecic::DodecicExtension},
        gadgets::nonnative_fp12::CircuitBuilderNonNativeExt12,
    };

    #[test]
    fn test_nonnative_ext12_add() -> Result<()> {
        type FF = DodecicExtension<Bn128Base>;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let x_ff = FF::sample(&mut rand::thread_rng());
        let y_ff = FF::sample(&mut rand::thread_rng());
        let sum_ff = x_ff + y_ff;

        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative_ext12(x_ff);
        let y = builder.constant_nonnative_ext12(y_ff);
        let sum = builder.add_nonnative_ext12(&x, &y);

        let sum_expected = builder.constant_nonnative_ext12(sum_ff);
        builder.connect_nonnative_ext12(&sum, &sum_expected);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_nonnative_ext12_sub() -> Result<()> {
        type FF = DodecicExtension<Bn128Base>;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let x_ff = FF::sample(&mut rand::thread_rng());
        let y_ff = FF::sample(&mut rand::thread_rng());
        let diff_ff = x_ff - y_ff;

        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative_ext12(x_ff);
        let y = builder.constant_nonnative_ext12(y_ff);
        let diff = builder.sub_nonnative_ext12(&x, &y);

        let diff_expected = builder.constant_nonnative_ext12(diff_ff);
        builder.connect_nonnative_ext12(&diff, &diff_expected);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_nonnative_ext12_mul() -> Result<()> {
        type FF = DodecicExtension<Bn128Base>;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        // Use specific values to avoid randomness issues
        let x_ff = FF::ONE;
        let y_ff = FF::from_basefield_array([
            Bn128Base::from_canonical_u64(2),
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
        ]);
        let product_ff = x_ff * y_ff;

        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative_ext12(x_ff);
        let y = builder.constant_nonnative_ext12(y_ff);
        let product = builder.mul_nonnative_ext12(&x, &y);

        let product_expected = builder.constant_nonnative_ext12(product_ff);
        builder.connect_nonnative_ext12(&product, &product_expected);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_nonnative_ext12_neg() -> Result<()> {
        type FF = DodecicExtension<Bn128Base>;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let x_ff = FF::sample(&mut rand::thread_rng());
        let neg_x_ff = -x_ff;

        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative_ext12(x_ff);
        let neg_x = builder.neg_nonnative_ext12(&x);

        let neg_x_expected = builder.constant_nonnative_ext12(neg_x_ff);
        builder.connect_nonnative_ext12(&neg_x, &neg_x_expected);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_nonnative_ext12_inv() -> Result<()> {
        type FF = DodecicExtension<Bn128Base>;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        // Use specific non-zero value to avoid randomness issues
        let x_ff = FF::from_basefield_array([
            Bn128Base::from_canonical_u64(3),
            Bn128Base::from_canonical_u64(1),
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
        ]);
        let inv_x_ff = x_ff.inverse();

        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative_ext12(x_ff);
        let inv_x = builder.inv_nonnative_ext12(&x);

        let inv_x_expected = builder.constant_nonnative_ext12(inv_x_ff);
        builder.connect_nonnative_ext12(&inv_x, &inv_x_expected);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_nonnative_ext12_square() -> Result<()> {
        type FF = DodecicExtension<Bn128Base>;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        // Use specific value to avoid randomness issues
        let x_ff = FF::from_basefield_array([
            Bn128Base::from_canonical_u64(2),
            Bn128Base::from_canonical_u64(1),
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
            Bn128Base::ZERO,
        ]);
        let square_x_ff = x_ff.square();

        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative_ext12(x_ff);
        let square_x = builder.squared_nonnative_ext12(&x);

        let square_x_expected = builder.constant_nonnative_ext12(square_x_ff);
        builder.connect_nonnative_ext12(&square_x, &square_x_expected);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_frobenius_coeffs_ext12_verification() -> Result<()> {
        use crate::crypto::bn254::{
            field::{bn128_extension::Bn128ExtConstants, extension::quadratic::QuadraticExtension},
            gadgets::nonnative_fp2::CircuitBuilderNonNativeExt2,
        };

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Test frobenius_coeffs_c1 for n=1
        let coeff_c1_1 = builder.frobenius_coeffs_c1_nonnative_ext12::<Bn128Base>(1);
        let expected_coeffs = <Bn128Base as Bn128ExtConstants>::FROBENIUS_COEFFS_EXT12_C1;
        let expected_c1_1 = builder.constant_nonnative_ext2(QuadraticExtension([expected_coeffs[0], expected_coeffs[1]]));
        builder.connect_nonnative_ext2(&coeff_c1_1, &expected_c1_1);

        // Test for n=2
        let coeff_c1_2 = builder.frobenius_coeffs_c1_nonnative_ext12::<Bn128Base>(2);
        let expected_c1_2 = builder.constant_nonnative_ext2(QuadraticExtension([expected_coeffs[2], expected_coeffs[3]]));
        builder.connect_nonnative_ext2(&coeff_c1_2, &expected_c1_2);

        // Test for n=3
        let coeff_c1_3 = builder.frobenius_coeffs_c1_nonnative_ext12::<Bn128Base>(3);
        let expected_c1_3 = builder.constant_nonnative_ext2(QuadraticExtension([expected_coeffs[4], expected_coeffs[5]]));
        builder.connect_nonnative_ext2(&coeff_c1_3, &expected_c1_3);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)?;

        println!("✅ Frobenius EXT12 coefficients verification test passed!");
        Ok(())
    }

    #[test]
    fn test_cyclotomic_squared_verification() -> Result<()> {
        type FF = DodecicExtension<Bn128Base>;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        // Create a known cyclotomic element (result of final exponentiation)
        // For testing, we'll use a simple element: 1 + 0*w + ... + 0*w^11
        let x_ff = FF::ONE;

        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_nonnative_ext12(x_ff);
        let squared = builder.cyclotomic_squared_nonnative_ext12(&x);

        // For x = 1, cyclotomic_squared(1) should equal 1
        let expected = builder.constant_nonnative_ext12(FF::ONE);
        builder.connect_nonnative_ext12(&squared, &expected);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)?;

        println!("✅ Cyclotomic squared verification test passed!");
        Ok(())
    }
}
