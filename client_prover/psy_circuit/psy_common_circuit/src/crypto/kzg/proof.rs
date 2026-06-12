use plonky2::{field::extension::Extendable, hash::hash_types::RichField};

use crate::crypto::{bn254::gadgets::g1::G1AffineTarget, secp256k1::ecdsa::curve::curve_types::AffinePoint};

#[derive(Clone, Debug)]
pub struct KZGProofTarget<F: RichField + Extendable<D>, const D: usize> {
    pub w: G1AffineTarget<F, D>,
}

#[derive(Clone, Debug)]
pub struct KZGProof {
    pub w: AffinePoint<crate::crypto::bn254::curve::g1::G1>,
}
