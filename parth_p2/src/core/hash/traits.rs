use parth_core::crypto::hash::traits::MerkleHasher;
use parth_core::crypto::hash::traits::MerkleZeroHasher;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::Hasher;

use crate::core::hash::qhashout::QHashOut;
pub trait QHasher<F: RichField> {
    fn q_two_to_one(left: QHashOut<F>, right: QHashOut<F>) -> QHashOut<F>;
}

pub trait QAlgebraicHasher<F: RichField>: AlgebraicHasher<F> + MerkleHasher<QHashOut<F>> + MerkleHasher<HashOut<F>> + BasicFieldHasher<F> {}
pub trait QAlgebraicZeroHasher<F: RichField>: QAlgebraicHasher<F> + MerkleZeroHasher<QHashOut<F>> + MerkleZeroHasher<HashOut<F>> {}

pub trait BasicFieldHasher<F: RichField> {
    fn hash_many(elements: &[F]) -> HashOut<F>;
    fn hash_many_pad(elements: &[F]) -> HashOut<F>;
    fn two_to_one(left: HashOut<F>, right: HashOut<F>) -> HashOut<F>;
}
/* 
impl<H:AlgebraicHasher<F>, F: RichField> BasicFieldHasher<F> for H {
    fn hash_many(elements: &[F]) -> HashOut<F> {
        H::hash_no_pad(elements)
    }

    fn hash_many_pad(elements: &[F]) -> HashOut<F> {
        H::hash_pad(elements)
    }

    fn two_to_one(left: HashOut<F>, right: HashOut<F>) -> HashOut<F> {
        H::two_to_one(left, right)
    }
}*/


impl<F: RichField> BasicFieldHasher<F> for PoseidonHash{
    fn hash_many(elements: &[F]) -> HashOut<F> {
        PoseidonHash::hash_no_pad(elements)
    }

    fn hash_many_pad(elements: &[F]) -> HashOut<F> {
        PoseidonHash::hash_pad(elements)
    }

    fn two_to_one(left: HashOut<F>, right: HashOut<F>) -> HashOut<F> {
        <PoseidonHash as Hasher<F>>::two_to_one(left, right)
    }
}
pub trait FieldQHasher<F: RichField> {
    fn hash_many(elements: &[F]) -> HashOut<F>;
    fn hash_many_pad(elements: &[F]) -> HashOut<F>;
    fn two_to_one(left: HashOut<F>, right: HashOut<F>) -> HashOut<F>;

    fn q_hash_many(elements: &[F]) -> QHashOut<F>;
    fn q_hash_many_pad(elements: &[F]) -> QHashOut<F>;
    fn q_two_to_one(left: QHashOut<F>, right: QHashOut<F>) -> QHashOut<F>;
}
pub trait FieldHasher<F: RichField>: FieldQHasher<F> {}
impl<H: BasicFieldHasher<F>, F: RichField> FieldQHasher<F> for H {
    fn hash_many(elements: &[F]) -> HashOut<F> {
        <H as BasicFieldHasher<F>>::hash_many(elements)
    }

    fn hash_many_pad(elements: &[F]) -> HashOut<F> {
        <H as BasicFieldHasher<F>>::hash_many_pad(elements)
    }

    fn two_to_one(left: HashOut<F>, right: HashOut<F>) -> HashOut<F> {
        <H as BasicFieldHasher<F>>::two_to_one(left, right)
    }

    fn q_hash_many(elements: &[F]) -> QHashOut<F> {
        QHashOut(<H as BasicFieldHasher<F>>::hash_many(elements))
    }

    fn q_hash_many_pad(elements: &[F]) -> QHashOut<F> {
        QHashOut(<H as BasicFieldHasher<F>>::hash_many(elements))
    }

    fn q_two_to_one(left: QHashOut<F>, right: QHashOut<F>) -> QHashOut<F> {
        QHashOut(<H as BasicFieldHasher<F>>::two_to_one(left.0, right.0))
    }
}


impl<F: RichField> MerkleHasher<QHashOut<F>> for PoseidonHasher {
    fn two_to_one(left: &QHashOut<F>, right: &QHashOut<F>) -> QHashOut<F> {
        <PoseidonHasher as FieldQHasher<F>>::q_two_to_one(*left, *right)
    }
}
impl<F: RichField> MerkleHasher<HashOut<F>> for PoseidonHasher {
    fn two_to_one(left: &HashOut<F>, right: &HashOut<F>) -> HashOut<F> {
        <PoseidonHasher as FieldQHasher<F>>::two_to_one(*left, *right)
    }
}

pub struct PoseidonHasher;
impl<F: RichField> BasicFieldHasher<F> for PoseidonHasher {
    fn hash_many(elements: &[F]) -> HashOut<F> {
        PoseidonHash::hash_no_pad(elements)
    }

    fn hash_many_pad(elements: &[F]) -> HashOut<F> {
        PoseidonHash::hash_pad(elements)
    }

    fn two_to_one(left: HashOut<F>, right: HashOut<F>) -> HashOut<F> {
        <PoseidonHash as Hasher<F>>::two_to_one(left, right)
    }
}
