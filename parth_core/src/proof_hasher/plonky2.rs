#[cfg(feature = "proof_hasher_plonky2_goldilocks")]
use plonky2::{hash::hash_types::RichField, plonk::config::AlgebraicHasher};

#[cfg(feature = "proof_hasher_plonky2_goldilocks")]
use crate::{crypto::hash::traits::FieldQHasher, pgoldilocks::QHashOut};



#[cfg(not(feature = "proof_hasher_plonky2_goldilocks"))]
pub trait MaybeBasicFieldTraitsPlonky2Goldilocks {}
#[cfg(not(feature = "proof_hasher_plonky2_goldilocks"))]
impl<F> MaybeBasicFieldTraitsPlonky2Goldilocks for F {}

#[cfg(not(feature = "proof_hasher_plonky2_goldilocks"))]
pub trait MaybePlonky2AlgebraicHasher<F: MaybeBasicFieldTraitsPlonky2Goldilocks> {}
#[cfg(not(feature = "proof_hasher_plonky2_goldilocks"))]
impl<F: MaybeBasicFieldTraitsPlonky2Goldilocks, Hasher> MaybePlonky2AlgebraicHasher<F> for Hasher {}




#[cfg(feature = "proof_hasher_plonky2_goldilocks")]
pub trait MaybeBasicFieldTraitsPlonky2Goldilocks: RichField {}
#[cfg(feature = "proof_hasher_plonky2_goldilocks")]
impl<F: RichField> MaybeBasicFieldTraitsPlonky2Goldilocks for F {}
#[cfg(feature = "proof_hasher_plonky2_goldilocks")]
pub trait MaybePlonky2AlgebraicHasher<F: MaybeBasicFieldTraitsPlonky2Goldilocks>: AlgebraicHasher<F> + FieldQHasher<F, QHashOut<F>> {}
#[cfg(feature = "proof_hasher_plonky2_goldilocks")]
impl<F: MaybeBasicFieldTraitsPlonky2Goldilocks, Hasher: AlgebraicHasher<F> + FieldQHasher<F, QHashOut<F>>> MaybePlonky2AlgebraicHasher<F> for Hasher {}

