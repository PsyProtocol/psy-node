use std::marker::PhantomData;

use num::BigUint;
use plonky2::{
    field::{
        extension::Extendable,
        types::{Field, PrimeField},
    },
    hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::crypto::{
    bn254::{
        curve::g2::G2,
        field::{
            bn128_base::Bn128Base,
            extension::{dodecic::DodecicExtension, quadratic::QuadraticExtension},
        },
        gadgets::{
            g1::G1AffineTarget,
            nonnative_fp::{CircuitBuilderNonNative, NonNativeTarget},
            nonnative_fp12::{CircuitBuilderNonNativeExt12, NonNativeTargetExt12},
            nonnative_fp2::{CircuitBuilderNonNativeExt2, NonNativeTargetExt2},
        },
    },
    secp256k1::ecdsa::curve::curve_types::{AffinePoint, Curve},
};

pub const ATE_LOOP_COUNT: [u64; 4] = [0x9d797039be763ba8, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000];

#[allow(dead_code)]
fn biguint_from_array(arr: [u64; 4]) -> BigUint {
    BigUint::from_slice(&[
        arr[0] as u32,
        (arr[0] >> 32) as u32,
        arr[1] as u32,
        (arr[1] >> 32) as u32,
        arr[2] as u32,
        (arr[2] >> 32) as u32,
        arr[3] as u32,
        (arr[3] >> 32) as u32,
    ])
}

#[derive(Clone, Debug)]
pub struct AffinePointTargetG2<FF: Field> {
    pub x: NonNativeTargetExt2<FF>,
    pub y: NonNativeTargetExt2<FF>,
}

#[derive(Clone, Debug)]
pub struct JacobianPointTargetG2<FF: Field> {
    pub x: NonNativeTargetExt2<FF>,
    pub y: NonNativeTargetExt2<FF>,
    pub z: NonNativeTargetExt2<FF>,
}

#[derive(Clone, Debug)]
pub struct EllCoefficientsTarget<FF: Field> {
    pub ell_0: NonNativeTargetExt2<FF>,
    pub ell_vw: NonNativeTargetExt2<FF>,
    pub ell_vv: NonNativeTargetExt2<FF>,
}

#[derive(Clone, Debug)]
pub struct G2PreComputeTarget<FF: Field> {
    pub q: AffinePointTargetG2<FF>,
    pub coeffs: Vec<EllCoefficientsTarget<FF>>,
}

pub trait CircuitBuilderPairing<F: RichField + Extendable<D>, const D: usize> {
    fn pairing<
        FF: PrimeField + Extendable<2> + Extendable<6> + Extendable<12>,
        G1: Curve<BaseField = FF>,
        G2: Curve<BaseField = QuadraticExtension<FF>>,
    >(
        &mut self,
        p: &G1AffineTarget<F, D>,
        q: &AffinePointTargetG2<G1::BaseField>,
    ) -> NonNativeTargetExt12<G1::BaseField>;
}

pub trait CircuitBuilderCurveG2<F: RichField + Extendable<D>, const D: usize> {
    fn add_g2<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        a: &AffinePointTargetG2<FF>,
        b: &AffinePointTargetG2<FF>,
    ) -> AffinePointTargetG2<FF>;

    fn neg_g2<FF: PrimeField + Extendable<2>>(&mut self, p: &AffinePointTargetG2<FF>) -> AffinePointTargetG2<FF>;

    fn precompute<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        p: &AffinePointTargetG2<FF>,
    ) -> G2PreComputeTarget<FF>;

    fn miller_loop<C: Curve<BaseField = FF>, FF: PrimeField + Extendable<2> + Extendable<6> + Extendable<12>>(
        &mut self,
        g1: &G1AffineTarget<F, D>,
        precomp: &G2PreComputeTarget<FF>,
    ) -> NonNativeTargetExt12<FF>;

    fn to_jacobian_g2<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        p: &AffinePointTargetG2<FF>,
    ) -> JacobianPointTargetG2<FF>;

    fn to_affine_g2<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        p: &JacobianPointTargetG2<FF>,
    ) -> AffinePointTargetG2<FF>;

    fn doubling_step_for_flipped_miller_loop<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        p: &JacobianPointTargetG2<FF>,
    ) -> (JacobianPointTargetG2<FF>, EllCoefficientsTarget<FF>);

    fn mixed_addition_step_for_flipped_miller_loop<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        r: &JacobianPointTargetG2<FF>,
        p: &AffinePointTargetG2<FF>,
    ) -> (JacobianPointTargetG2<FF>, EllCoefficientsTarget<FF>);

    fn mul_by_q<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        p: &AffinePointTargetG2<FF>,
    ) -> AffinePointTargetG2<FF>;

    fn constant_affine_point_g2<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        point: AffinePoint<C>,
    ) -> AffinePointTargetG2<FF>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderPairing<F, D> for CircuitBuilder<F, D> {
    fn pairing<
        FF: PrimeField + Extendable<2> + Extendable<6> + Extendable<12>,
        G1: Curve<BaseField = FF>,
        G2: Curve<BaseField = QuadraticExtension<FF>>,
    >(
        &mut self,
        p: &G1AffineTarget<F, D>,
        q: &AffinePointTargetG2<G1::BaseField>,
    ) -> NonNativeTargetExt12<G1::BaseField> {
        println!("Step 1: Precompute line coefficients for G2 point...");
        let pre = self.precompute::<G2, G1::BaseField>(q);
        println!("  - Precomputed {} coefficients", pre.coeffs.len());

        println!("Step 2: Miller loop computation...");
        let m = self.miller_loop::<G1, G1::BaseField>(p, &pre);
        println!("  - Miller loop completed");

        println!("Step 3: Final exponentiation (two chunks)...");
        println!("  - First chunk...");
        let res = self.final_exponentiation_first_chunk(&m);
        println!("  - Last chunk...");
        let result = self.final_exponentiation_last_chunk(&res);
        println!("  - Final exponentiation completed");

        result
    }
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderCurveG2<F, D> for CircuitBuilder<F, D> {
    fn add_g2<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        a: &AffinePointTargetG2<FF>,
        b: &AffinePointTargetG2<FF>,
    ) -> AffinePointTargetG2<FF> {
        let AffinePointTargetG2 { x: x1, y: y1 } = a;
        let AffinePointTargetG2 { x: x2, y: y2 } = b;

        // Check if x-coordinates are equal
        let x_equal = self.is_equal_ext2(x1, x2);

        // Check if y-coordinates are equal (same point - need to double)
        let y_equal = self.is_equal_ext2(y1, y2);
        let should_double = self.and(x_equal, y_equal);

        // Check if y-coordinates are opposite (result is infinity)
        let neg_y2 = self.neg_nonnative_ext2(y2);
        let y_opposite = self.is_equal_ext2(y1, &neg_y2);
        let should_be_infinity = self.and(x_equal, y_opposite);

        // Compute doubling result
        // Check if y is zero (for both components)
        let y0_is_zero = self.is_zero_nonnative(&y1.c0);
        let y1_is_zero = self.is_zero_nonnative(&y1.c1);
        let y_is_zero = self.and(y0_is_zero, y1_is_zero);

        let x_squared = self.squared_nonnative_ext2(x1);
        let two_x_squared = self.add_nonnative_ext2(&x_squared, &x_squared);
        let three_x_squared = self.add_nonnative_ext2(&x_squared, &two_x_squared);
        let two_y = self.add_nonnative_ext2(y1, y1);

        let one = self.one_nonnative();
        let zero = self.zero_nonnative();
        let one_ext2 = NonNativeTargetExt2 {
            c0: one,
            c1: zero,
            _phantom: PhantomData,
        };
        let two_y_safe = self.select_ext2(y_is_zero, &one_ext2, &two_y);
        let two_y_inv = self.inv_nonnative_ext2(&two_y_safe);
        let slope_double = self.mul_nonnative_ext2(&three_x_squared, &two_y_inv);

        let slope_double_squared = self.squared_nonnative_ext2(&slope_double);
        let two_x = self.add_nonnative_ext2(x1, x1);
        let x3_double = self.sub_nonnative_ext2(&slope_double_squared, &two_x);

        let x_diff_double = self.sub_nonnative_ext2(x1, &x3_double);
        let y3_double_temp = self.mul_nonnative_ext2(&slope_double, &x_diff_double);
        let y3_double = self.sub_nonnative_ext2(&y3_double_temp, y1);

        // Compute regular addition result (with safe division)
        let u = self.sub_nonnative_ext2(y2, y1);
        let v = self.sub_nonnative_ext2(x2, x1);
        let v_safe = self.select_ext2(x_equal, &one_ext2, &v);
        let v_inv = self.inv_nonnative_ext2(&v_safe);
        let s = self.mul_nonnative_ext2(&u, &v_inv);
        let s_squared = self.mul_nonnative_ext2(&s, &s);
        let x_sum = self.add_nonnative_ext2(x2, x1);
        let x3_add = self.sub_nonnative_ext2(&s_squared, &x_sum);
        let x_diff_add = self.sub_nonnative_ext2(x1, &x3_add);
        let prod = self.mul_nonnative_ext2(&s, &x_diff_add);
        let y3_add = self.sub_nonnative_ext2(&prod, y1);

        // Select the appropriate result
        let zero = self.zero_nonnative_ext2();
        let x3_normal = self.select_ext2(should_double, &x3_double, &x3_add);
        let y3_normal = self.select_ext2(should_double, &y3_double, &y3_add);

        let x3 = self.select_ext2(should_be_infinity, &zero, &x3_normal);
        let y3 = self.select_ext2(should_be_infinity, &zero, &y3_normal);

        AffinePointTargetG2 { x: x3, y: y3 }
    }

    fn neg_g2<FF: PrimeField + Extendable<2>>(&mut self, p: &AffinePointTargetG2<FF>) -> AffinePointTargetG2<FF> {
        let neg_y = self.neg_nonnative_ext2(&p.y);
        AffinePointTargetG2 { x: p.x.clone(), y: neg_y }
    }

    fn constant_affine_point_g2<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        point: AffinePoint<C>,
    ) -> AffinePointTargetG2<FF> {
        debug_assert!(!point.zero);
        AffinePointTargetG2 {
            x: self.constant_nonnative_ext2(point.x),
            y: self.constant_nonnative_ext2(point.y),
        }
    }

    fn to_jacobian_g2<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        p: &AffinePointTargetG2<FF>,
    ) -> JacobianPointTargetG2<FF> {
        JacobianPointTargetG2 {
            x: p.x.clone(),
            y: p.y.clone(),
            z: self.constant_nonnative_ext2(QuadraticExtension([FF::ONE, FF::ZERO])),
        }
    }

    fn to_affine_g2<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        p: &JacobianPointTargetG2<FF>,
    ) -> AffinePointTargetG2<FF> {
        // Following ark-r1cs-std approach but using existing components
        // Since inv_nonnative_ext2 uses inv_nonnative internally which will fail on
        // zero, and G2 points in KZG are never infinity, we can use it directly

        // Note: If we ever need to handle infinity for G2, we would need to:
        // 1. Check if z is zero: let z_is_zero = self.is_zero_nonnative_ext2(&p.z);
        // 2. Create a safe version of inv_nonnative_ext2 that returns 0 when input is 0
        // 3. Add constraint: z_inv * z = !z_is_zero

        let z_inv = self.inv_nonnative_ext2(&p.z);
        let z_inv_squared = self.mul_nonnative_ext2(&z_inv, &z_inv);
        let x = self.mul_nonnative_ext2(&p.x, &z_inv_squared);
        let z_inv_cubed = self.mul_nonnative_ext2(&z_inv_squared, &z_inv);
        let y = self.mul_nonnative_ext2(&p.y, &z_inv_cubed);

        AffinePointTargetG2 { x, y }
    }

    fn precompute<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        p: &AffinePointTargetG2<FF>,
    ) -> G2PreComputeTarget<FF> {
        let mut r = self.to_jacobian_g2::<C, FF>(p);
        let mut coeffs = Vec::with_capacity(102);
        let mut found_one = false;
        let mut bit_count = 0;

        for (j_idx, j) in ATE_LOOP_COUNT.iter().rev().enumerate() {
            if j_idx == 0 {
                println!("  Processing ATE_LOOP_COUNT[{}] = 0x{:x}", 3 - j_idx, j);
            }
            for i in (0..64).rev() {
                if !found_one {
                    found_one = (j >> i) & 1 == 1;
                    continue;
                }
                bit_count += 1;

                let (r0, coeff) = self.doubling_step_for_flipped_miller_loop::<C, FF>(&r);
                r = r0;
                coeffs.push(coeff);

                if (j >> i) & 1 == 1 {
                    let (r0, coeff) = self.mixed_addition_step_for_flipped_miller_loop::<C, FF>(&r, p);
                    r = r0;
                    coeffs.push(coeff);
                }

                if bit_count % 10 == 0 {
                    println!("    Processed {} bits, {} coefficients", bit_count, coeffs.len());
                }
            }
        }

        let q1 = self.mul_by_q::<C, FF>(p);
        let mul_by_q = self.mul_by_q::<C, FF>(&q1);
        let q2 = <Self as CircuitBuilderCurveG2<F, D>>::neg_g2::<FF>(self, &mul_by_q);

        let (r0, coeff) = self.mixed_addition_step_for_flipped_miller_loop::<C, FF>(&r, &q1);
        r = r0;
        coeffs.push(coeff);
        let (_, coeff) = self.mixed_addition_step_for_flipped_miller_loop::<C, FF>(&r, &q2);
        coeffs.push(coeff);

        G2PreComputeTarget { q: p.clone(), coeffs }
    }

    fn miller_loop<C: Curve<BaseField = FF>, FF: PrimeField + Extendable<2> + Extendable<6> + Extendable<12>>(
        &mut self,
        g1: &G1AffineTarget<F, D>,
        precomp: &G2PreComputeTarget<FF>,
    ) -> NonNativeTargetExt12<FF> {
        let mut f = self.constant_nonnative_ext12(DodecicExtension::ONE);
        let mut idx = 0;
        let mut found_one = false;

        let g1_x: &NonNativeTarget<FF> = unsafe { std::mem::transmute(&g1.x) };
        let g1_y: &NonNativeTarget<FF> = unsafe { std::mem::transmute(&g1.y) };

        for j in ATE_LOOP_COUNT.iter().rev() {
            for i in (0..64).rev() {
                if !found_one {
                    found_one = (j >> i) & 1 == 1;
                    continue;
                }

                let c = &precomp.coeffs[idx];
                idx += 1;
                f = self.squared_nonnative_ext12(&f);
                let _ell_vw = self.scale_nonnative_ext2(&c.ell_vw, g1_y);
                let _ell_vv = self.scale_nonnative_ext2(&c.ell_vv, g1_x);
                // f = self.mul_by_024(&f, &c.ell_0, &ell_vw, &ell_vv);

                if (j >> i) & 1 == 1 {
                    let c = &precomp.coeffs[idx];
                    idx += 1;
                    let _ell_vw = self.scale_nonnative_ext2(&c.ell_vw, g1_y);
                    let _ell_vv = self.scale_nonnative_ext2(&c.ell_vv, g1_x);
                    // f = self.mul_by_024(&f, &c.ell_0, &ell_vw, &ell_vv);
                }
            }
        }

        let c = &precomp.coeffs[idx];
        idx += 1;
        let _ell_vw = self.scale_nonnative_ext2(&c.ell_vw, g1_y);
        let _ell_vv = self.scale_nonnative_ext2(&c.ell_vv, g1_x);
        // f = self.mul_by_024(&f, &c.ell_0, &ell_vw, &ell_vv);

        let c = &precomp.coeffs[idx];
        let _ell_vw = self.scale_nonnative_ext2(&c.ell_vw, g1_y);
        let _ell_vv = self.scale_nonnative_ext2(&c.ell_vv, g1_x);
        // f = self.mul_by_024(&f, &c.ell_0, &ell_vw, &ell_vv);

        f
    }

    fn doubling_step_for_flipped_miller_loop<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        p: &JacobianPointTargetG2<FF>,
    ) -> (JacobianPointTargetG2<FF>, EllCoefficientsTarget<FF>) {
        // Use G2::INV_TWO for BN128
        let two_inv = if core::any::TypeId::of::<FF>() == core::any::TypeId::of::<Bn128Base>() {
            // Safe to transmute since we checked the type
            let inv_two_base = G2::INV_TWO.0[0];
            unsafe {
                let transmuted: FF = core::mem::transmute_copy(&inv_two_base);
                self.constant_nonnative(transmuted)
            }
        } else {
            self.constant_nonnative(FF::from_canonical_u64(2).inverse())
        };

        let mut a = self.mul_nonnative_ext2(&p.x, &p.y);
        a = self.scale_nonnative_ext2(&a, &two_inv);
        let b = self.squared_nonnative_ext2(&p.y);
        let c = self.squared_nonnative_ext2(&p.z);
        let mut d = self.add_nonnative_ext2(&c, &c);
        d = self.add_nonnative_ext2(&d, &c);

        // Use C::B for the curve parameter
        let mut e = self.constant_nonnative_ext2(C::B);
        e = self.mul_nonnative_ext2(&e, &d);
        let mut f = self.add_nonnative_ext2(&e, &e);
        f = self.add_nonnative_ext2(&f, &e);
        let mut g = self.add_nonnative_ext2(&b, &f);
        g = self.scale_nonnative_ext2(&g, &two_inv);
        let mut h = self.add_nonnative_ext2(&p.y, &p.z);
        h = self.squared_nonnative_ext2(&h);
        h = self.sub_nonnative_ext2(&h, &b);
        h = self.sub_nonnative_ext2(&h, &c);
        let i = self.sub_nonnative_ext2(&e, &b);
        let j = self.squared_nonnative_ext2(&p.x);
        let e_sq = self.squared_nonnative_ext2(&e);

        let mut x = self.sub_nonnative_ext2(&b, &f);
        x = self.mul_nonnative_ext2(&a, &x);
        let mut y = self.squared_nonnative_ext2(&g);
        let mut e_sq_3 = self.add_nonnative_ext2(&e_sq, &e_sq);
        e_sq_3 = self.add_nonnative_ext2(&e_sq_3, &e_sq);
        y = self.sub_nonnative_ext2(&y, &e_sq_3);
        let z = self.mul_nonnative_ext2(&b, &h);

        let ell_0 = self.mul_by_nonresidue_nonnative_ext2(&i);
        let ell_vw = self.neg_nonnative_ext2(&h);
        let mut ell_vv = self.add_nonnative_ext2(&j, &j);
        ell_vv = self.add_nonnative_ext2(&ell_vv, &j);

        (JacobianPointTargetG2 { x, y, z }, EllCoefficientsTarget { ell_0, ell_vw, ell_vv })
    }

    fn mixed_addition_step_for_flipped_miller_loop<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        r: &JacobianPointTargetG2<FF>,
        base: &AffinePointTargetG2<FF>,
    ) -> (JacobianPointTargetG2<FF>, EllCoefficientsTarget<FF>) {
        let mut d = self.mul_nonnative_ext2(&r.z, &base.x);
        d = self.sub_nonnative_ext2(&r.x, &d);
        let mut e = self.mul_nonnative_ext2(&r.z, &base.y);
        e = self.sub_nonnative_ext2(&r.y, &e);
        let f = self.squared_nonnative_ext2(&d);
        let g = self.squared_nonnative_ext2(&e);
        let h = self.mul_nonnative_ext2(&d, &f);
        let i = self.mul_nonnative_ext2(&r.x, &f);
        let mut j = self.mul_nonnative_ext2(&r.z, &g);
        j = self.add_nonnative_ext2(&j, &h);
        j = self.sub_nonnative_ext2(&j, &i);
        j = self.sub_nonnative_ext2(&j, &i);
        let x = self.mul_nonnative_ext2(&d, &j);
        let mut y = self.sub_nonnative_ext2(&i, &j);
        y = self.mul_nonnative_ext2(&e, &y);
        let h_y = self.mul_nonnative_ext2(&h, &r.y);
        y = self.sub_nonnative_ext2(&y, &h_y);
        let z = self.mul_nonnative_ext2(&r.z, &h);
        let e_x = self.mul_nonnative_ext2(&e, &base.x);
        let d_y = self.mul_nonnative_ext2(&d, &base.y);
        let mut ell_0 = self.sub_nonnative_ext2(&e_x, &d_y);
        ell_0 = self.mul_by_nonresidue_nonnative_ext2(&ell_0);
        let ell_vv = self.neg_nonnative_ext2(&e);
        let ell_vw = d;
        (JacobianPointTargetG2 { x, y, z }, EllCoefficientsTarget { ell_0, ell_vv, ell_vw })
    }

    fn mul_by_q<C: Curve<BaseField = QuadraticExtension<FF>>, FF: PrimeField + Extendable<2>>(
        &mut self,
        p: &AffinePointTargetG2<FF>,
    ) -> AffinePointTargetG2<FF> {
        let x_frobenius = self.frobenius_map_nonnative_ext2(&p.x, 1);
        let y_frobenius = self.frobenius_map_nonnative_ext2(&p.y, 1);

        // For BN128, use hardcoded constants
        // Import G2 to get the constants
        use crate::crypto::bn254::{curve::g2::G2, field::bn128_base::Bn128Base};

        // TWIST_MUL_BY_Q_X = QuadraticExtension([
        //     Bn128Base([13075984984163199792, 3782902503040509012,
        // 8791150885551868305, 1825854335138010348]),
        //     Bn128Base([7963664994991228759, 12257807996192067905,
        // 13179524609921305146, 2767831111890561987]) ])
        let twist_mul_by_q_x = if core::any::TypeId::of::<FF>() == core::any::TypeId::of::<Bn128Base>() {
            // Safe to transmute since we checked the type
            let g2_const = G2::TWIST_MUL_BY_Q_X;
            unsafe {
                let transmuted: QuadraticExtension<FF> = core::mem::transmute_copy(&g2_const);
                self.constant_nonnative_ext2(transmuted)
            }
        } else {
            // For other field types, create from BigUint
            self.constant_nonnative_ext2(QuadraticExtension::<FF>([
                FF::from_noncanonical_biguint(BigUint::from_slice(
                    &[
                        13075984984163199792u64,
                        3782902503040509012u64,
                        8791150885551868305u64,
                        1825854335138010348u64,
                    ]
                    .iter()
                    .flat_map(|&x| vec![x as u32, (x >> 32) as u32])
                    .collect::<Vec<_>>(),
                )),
                FF::from_noncanonical_biguint(BigUint::from_slice(
                    &[
                        7963664994991228759u64,
                        12257807996192067905u64,
                        13179524609921305146u64,
                        2767831111890561987u64,
                    ]
                    .iter()
                    .flat_map(|&x| vec![x as u32, (x >> 32) as u32])
                    .collect::<Vec<_>>(),
                )),
            ]))
        };

        // TWIST_MUL_BY_Q_Y
        let twist_mul_by_q_y = if core::any::TypeId::of::<FF>() == core::any::TypeId::of::<Bn128Base>() {
            // Safe to transmute since we checked the type
            let g2_const = G2::TWIST_MUL_BY_Q_Y;
            unsafe {
                let transmuted: QuadraticExtension<FF> = core::mem::transmute_copy(&g2_const);
                self.constant_nonnative_ext2(transmuted)
            }
        } else {
            // For other field types, create from BigUint
            self.constant_nonnative_ext2(QuadraticExtension::<FF>([
                FF::from_noncanonical_biguint(BigUint::from_slice(
                    &[
                        16482010305593259561u64,
                        13488546290961988299u64,
                        3578621962720924518u64,
                        2681173117283399901u64,
                    ]
                    .iter()
                    .flat_map(|&x| vec![x as u32, (x >> 32) as u32])
                    .collect::<Vec<_>>(),
                )),
                FF::from_noncanonical_biguint(BigUint::from_slice(
                    &[
                        11661927080404088775u64,
                        553939530661941723u64,
                        7860678177968807019u64,
                        3208568454732775116u64,
                    ]
                    .iter()
                    .flat_map(|&x| vec![x as u32, (x >> 32) as u32])
                    .collect::<Vec<_>>(),
                )),
            ]))
        };

        AffinePointTargetG2 {
            x: self.mul_nonnative_ext2(&twist_mul_by_q_x, &x_frobenius),
            y: self.mul_nonnative_ext2(&twist_mul_by_q_y, &y_frobenius),
        }
    }
}

#[cfg(test)]
mod tests {
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use super::*;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_precompute_g2() -> anyhow::Result<()> {
        use crate::crypto::{bn254::curve::G2, secp256k1::ecdsa::curve::curve_types::Curve};

        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create a G2 point in the circuit
        let g2_gen = G2::GENERATOR_AFFINE;
        let g2_target = builder.constant_affine_point_g2::<G2, Bn128Base>(g2_gen);

        // Try precompute operation
        println!("Starting precompute...");
        let coeffs = builder.precompute::<G2, Bn128Base>(&g2_target);
        println!("Precompute completed with {} coefficients", coeffs.coeffs.len());

        // Build circuit
        let circuit = builder.build::<C>();
        println!("Circuit built with {} gates", circuit.common.gates.len());

        Ok(())
    }

    #[test]
    fn test_g2_circuit_operations() -> anyhow::Result<()> {
        use crate::crypto::{bn254::curve::G2, secp256k1::ecdsa::curve::curve_types::Curve};

        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create a G2 point in the circuit
        let g2_gen = G2::GENERATOR_AFFINE;
        let g2_target = builder.constant_affine_point_g2::<G2, Bn128Base>(g2_gen);

        // Try mul_by_q operation which is used in pairing
        let _result = builder.mul_by_q::<G2, Bn128Base>(&g2_target);

        println!("Created G2 point and doubled it in circuit");

        // Build circuit without proving
        let circuit = builder.build::<C>();
        println!("Circuit built with {} gates", circuit.common.gates.len());

        Ok(())
    }

    #[test]
    fn test_g2_basic_operations() -> anyhow::Result<()> {
        use crate::crypto::{bn254::curve::G2, secp256k1::ecdsa::curve::curve_types::Curve};

        // Test G2 generator
        let g2_gen = G2::GENERATOR_AFFINE;
        println!("G2 generator: x = {:?}", g2_gen.x);
        println!("G2 generator: y = {:?}", g2_gen.y);

        // Test that generator is on curve
        assert!(g2_gen.is_valid());

        // Test basic field arithmetic in Fp2
        let a = g2_gen.x;
        let b = g2_gen.y;
        let c = a + b;
        let d = a * b;

        println!("a + b = {:?}", c);
        println!("a * b = {:?}", d);

        // Test mul_by_nonresidue
        let e = a.mul_by_nonresidue_bn128();
        println!("a.mul_by_nonresidue_bn128() = {:?}", e);

        Ok(())
    }

    #[test]
    fn test_pairing() -> anyhow::Result<()> {
        use plonky2::{
            iop::witness::PartialWitness,
            plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
        };

        use crate::crypto::bn254::{
            curve::{G1, G2},
            field::extension::dodecic::DodecicExtension,
            gadgets::g1::G1AffineTarget,
        };

        // Skip logging setup - we don't have env_logger dependency

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // These constants are not used in this test

        let p = G1AffineTarget::<F, D> {
            x: builder.constant_nonnative(Bn128Base([
                18009135459904726766,
                2053664114473314749,
                9535470248130011749,
                3479289040628672906,
            ])),
            y: builder.constant_nonnative(Bn128Base([
                6225675676338262706,
                4510937524066860607,
                11348405336138879847,
                2021255424210394902,
            ])),
            is_infinity: builder._false(),
            _phantom: PhantomData,
        };

        let q = JacobianPointTargetG2 {
            x: builder.constant_nonnative_ext2(QuadraticExtension::<Bn128Base>([
                Bn128Base([2577798519503118397, 14034210771057369560, 14798801535089424299, 1731240919448670153]),
                Bn128Base([15909499412933957829, 12344152745192254056, 1185193310574937231, 760964259656302494]),
            ])),
            y: builder.constant_nonnative_ext2(QuadraticExtension::<Bn128Base>([
                Bn128Base([16827884672622421998, 756648877887862755, 18069298113966277418, 2110768940310013157]),
                Bn128Base([12195099017078129020, 6997443175976044100, 15957581681657247863, 752644145961255405]),
            ])),
            z: builder.constant_nonnative_ext2(QuadraticExtension::<Bn128Base>([
                Bn128Base([12079780699228388722, 791215766957020566, 2914756960274132770, 2602717870663046513]),
                Bn128Base([12691905162280913768, 89920551545646552, 12941976487854615151, 2355989044724612682]),
            ])),
        };
        let q_affine = builder.to_affine_g2::<G2, Bn128Base>(&q);

        let x_expected = builder.constant_nonnative_ext12(DodecicExtension::<Bn128Base>([
            Bn128Base([5261791323882946788, 5969279653909130133, 13914067258383528210, 94138518832923322]),
            Bn128Base([16452828235560020136, 14277920321324140450, 1808868257472119675, 34528199959501362]),
            Bn128Base([18153774717408091761, 4960813716655447740, 16877776237373176286, 111333703937892795]),
            Bn128Base([6177369533740206595, 5540475544632735388, 18239293933561841014, 2106733616315301007]),
            Bn128Base([12051797884938972865, 5452376490073186411, 13624941770027287332, 2556206152101805306]),
            Bn128Base([12875218175083744969, 18411108459922848687, 16205159152680096724, 2298321485788462962]),
            Bn128Base([14609934753813766369, 10831492163493656847, 9520417608604346386, 3185244767883521333]),
            Bn128Base([1210469375740710922, 12695443078599703490, 15456619824566231090, 1318481115027774681]),
            Bn128Base([12407907403893432531, 2577431929064026945, 13354667077106593055, 687277024136764940]),
            Bn128Base([16854887897954252879, 12456401038131277336, 4434193903233473879, 1222410746383484321]),
            Bn128Base([14754110002434578184, 3232557947137383979, 560992349178873120, 3162237541859216066]),
            Bn128Base([4982245430574873546, 2614584005832853337, 14785904332481227781, 1602384300921012077]),
        ]));

        let x = builder.pairing::<Bn128Base, G1, G2>(&p, &q_affine);
        builder.connect_nonnative_ext12(&x_expected, &x);

        println!("Building circuit...");
        println!("  - Number of gates: {}", builder.num_gates());
        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        let res = data.verify(proof);

        res
    }
}
