use plonky2::field::types::Field;
use serde::{Deserialize, Serialize};

use crate::crypto::{
    bn254::field::{bn128_base::Bn128Base, bn128_scalar::Bn128Scalar, extension::quadratic::QuadraticExtension},
    secp256k1::ecdsa::curve::curve_types::{AffinePoint, Curve},
};

#[derive(Debug, Copy, Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct G2;

impl G2 {
    pub const INV_TWO: QuadraticExtension<Bn128Base> = QuadraticExtension::<Bn128Base>([
        Bn128Base([9781510331150239090, 15059239858463337189, 10331104244869713732, 2249375503248834476]),
        Bn128Base::ZERO,
    ]);
    pub const TWIST_MUL_BY_Q_X: QuadraticExtension<Bn128Base> = QuadraticExtension::<Bn128Base>([
        Bn128Base([13075984984163199792, 3782902503040509012, 8791150885551868305, 1825854335138010348]),
        Bn128Base([7963664994991228759, 12257807996192067905, 13179524609921305146, 2767831111890561987]),
    ]);
    pub const TWIST_MUL_BY_Q_Y: QuadraticExtension<Bn128Base> = QuadraticExtension::<Bn128Base>([
        Bn128Base([16482010305593259561, 13488546290961988299, 3578621962720924518, 2681173117283399901]),
        Bn128Base([11661927080404088775, 553939530661941723, 7860678177968807019, 3208568454732775116]),
    ]);
}

impl Curve for G2 {
    type BaseField = QuadraticExtension<Bn128Base>;
    type ScalarField = Bn128Scalar;

    const A: QuadraticExtension<Bn128Base> = QuadraticExtension::<Bn128Base>([Bn128Base::ZERO, Bn128Base::ZERO]);
    const B: QuadraticExtension<Bn128Base> = QuadraticExtension::<Bn128Base>([
        Bn128Base([0x3bf938e377b802a8, 0x020b1b273633535d, 0x26b7edf049755260, 0x2514c6324384a86d]),
        Bn128Base([0x38e7ecccd1dcff67, 0x65f0b37d93ce0d3e, 0xd749d0dd22ac00aa, 0x0141b9ce4a688d4d]),
    ]);
    const GENERATOR_AFFINE: AffinePoint<Self> = AffinePoint {
        x: BN128G2_GENERATOR_X,
        y: BN128G2_GENERATOR_Y,
        zero: false,
    };
}

const BN128G2_GENERATOR_X: QuadraticExtension<Bn128Base> = QuadraticExtension::<Bn128Base>([
    Bn128Base([0x8e83b5d102bc2026, 0xdceb1935497b0172, 0xfbb8264797811adf, 0x19573841af96503b]),
    Bn128Base([0xafb4737da84c6140, 0x6043dd5a5802d8c4, 0x09e950fc52a02f86, 0x14fef0833aea7b6b]),
]);
const BN128G2_GENERATOR_Y: QuadraticExtension<Bn128Base> = QuadraticExtension::<Bn128Base>([
    Bn128Base([0x619dfa9d886be9f6, 0xfe7fd297f59e9b78, 0xff9e1a62231b7dfe, 0x28fd7eebae9e4206]),
    Bn128Base([0x64095b56c71856ee, 0xdc57f922327d3cbb, 0x55f935be33351076, 0x0da4a0e693fd6482]),
]);

#[cfg(test)]
mod tests {
    use num::BigUint;

    use crate::crypto::{
        bn254::{curve::g2::G2, field::bn128_scalar::Bn128Scalar},
        secp256k1::ecdsa::curve::curve_types::{AffinePoint, Curve, ProjectivePoint},
    };

    #[test]
    fn test_generator() {
        let g = G2::GENERATOR_AFFINE;
        assert!(g.is_valid());

        let neg_g = AffinePoint::<G2> {
            x: g.x,
            y: -g.y,
            zero: g.zero,
        };
        assert!(neg_g.is_valid());
    }

    #[test]
    fn test_naive_multiplication() {
        let g = G2::GENERATOR_PROJECTIVE;
        let ten = Bn128Scalar::from_canonical_u64(10);
        let product = mul_naive(ten, g);
        let sum = g + g + g + g + g + g + g + g + g + g;
        assert_eq!(product, sum);
    }

    #[test]
    fn test_g2_multiplication() {
        let lhs = Bn128Scalar::from_noncanonical_biguint(BigUint::from_slice(&[1111, 2222, 3333, 4444, 5555, 6666, 7777, 8888]));
        assert_eq!(G2::convert(lhs) * G2::GENERATOR_PROJECTIVE, mul_naive(lhs, G2::GENERATOR_PROJECTIVE));
    }

    fn mul_naive(lhs: Bn128Scalar, rhs: ProjectivePoint<G2>) -> ProjectivePoint<G2> {
        let mut g = rhs;
        let mut sum = ProjectivePoint::ZERO;
        for limb in lhs.to_canonical_biguint().to_u64_digits().iter() {
            for j in 0..64 {
                if (limb >> j & 1u64) != 0u64 {
                    sum = sum + g;
                }
                g = g.double();
            }
        }
        sum
    }
}
