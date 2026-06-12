pub mod g1;
pub mod g2;

pub use g1::G1;
pub use g2::G2;

pub use crate::crypto::secp256k1::ecdsa::curve::curve_types::{AffinePoint, ProjectivePoint};

pub type G1Affine = AffinePoint<G1>;
pub type G1Projective = ProjectivePoint<G1>;
pub type G2Affine = AffinePoint<G2>;
pub type G2Projective = ProjectivePoint<G2>;
