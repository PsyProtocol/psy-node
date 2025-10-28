
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

use crate::crypto::hash::traits::FieldQHasher;
use crate::crypto::hash::traits::MerkleHasher;
use crate::crypto::hash::traits::MerkleZeroHasher;
use crate::generic_traits::QStaticNamedType;
use crate::protocol::core_types::QFHasherU64;

use super::super::QHashOut;
type BF = GoldilocksField;
type BaseHashQ = QHashOut<BF>;
type BaseHashP2 = HashOut<BF>;

impl QStaticNamedType for PoseidonHash {
    fn q_static_type_name() -> &'static str {
        "PoseidonHash"
    }
}
pub struct PoseidonHasher;
impl FieldQHasher<BF, BaseHashQ> for PoseidonHasher {
    #[inline]
    fn q_two_to_one_ref(left: &BaseHashQ, right: &BaseHashQ) -> BaseHashQ {
        QHashOut(<PoseidonHash as Hasher<BF>>::two_to_one(left.0, right.0))
    }
    
    #[inline]
    fn q_hash_many(elements: &[BF]) -> BaseHashQ {
        QHashOut(PoseidonHash::hash_no_pad(elements))
    }
    
    #[inline]
    fn q_hash_many_pad(elements: &[BF]) -> BaseHashQ {
        QHashOut(<PoseidonHash as Hasher<BF>>::hash_pad(elements))
    }
    
    #[inline]
    fn q_two_to_one(left: BaseHashQ, right: BaseHashQ) -> BaseHashQ {
        QHashOut(<PoseidonHash as Hasher<BF>>::two_to_one(left.0, right.0))
    }
}
impl FieldQHasher<BF, BaseHashQ> for PoseidonHash {
    #[inline]
    fn q_two_to_one_ref(left: &BaseHashQ, right: &BaseHashQ) -> BaseHashQ {
        QHashOut(<PoseidonHash as Hasher<BF>>::two_to_one(left.0, right.0))
    }
    
    #[inline]
    fn q_hash_many(elements: &[BF]) -> BaseHashQ {
        QHashOut(PoseidonHash::hash_no_pad(elements))
    }
    
    #[inline]
    fn q_hash_many_pad(elements: &[BF]) -> BaseHashQ {
        QHashOut(<PoseidonHash as Hasher<BF>>::hash_pad(elements))
    }
    
    #[inline]
    fn q_two_to_one(left: BaseHashQ, right: BaseHashQ) -> BaseHashQ {
        QHashOut(<PoseidonHash as Hasher<BF>>::two_to_one(left.0, right.0))
    }
}

impl FieldQHasher<BF, BaseHashP2> for PoseidonHasher {
    #[inline]
    fn q_two_to_one_ref(left: &BaseHashP2, right: &BaseHashP2) -> BaseHashP2 {
        <PoseidonHash as Hasher<BF>>::two_to_one(*left, *right)
    }
    
    #[inline]
    fn q_hash_many(elements: &[BF]) -> BaseHashP2 {
        PoseidonHash::hash_no_pad(elements)
    }
    
    #[inline]
    fn q_hash_many_pad(elements: &[BF]) -> BaseHashP2 {
        <PoseidonHash as Hasher<BF>>::hash_pad(elements)
    }
    
    #[inline]
    fn q_two_to_one(left: BaseHashP2, right: BaseHashP2) -> BaseHashP2 {
        <PoseidonHash as Hasher<BF>>::two_to_one(left, right)
    }
}
impl FieldQHasher<BF, BaseHashP2> for PoseidonHash {
    #[inline]
    fn q_two_to_one_ref(left: &BaseHashP2, right: &BaseHashP2) -> BaseHashP2 {
        <PoseidonHash as Hasher<BF>>::two_to_one(*left, *right)
    }
    
    #[inline]
    fn q_hash_many(elements: &[BF]) -> BaseHashP2 {
        PoseidonHash::hash_no_pad(elements)
    }
    
    #[inline]
    fn q_hash_many_pad(elements: &[BF]) -> BaseHashP2 {
        <PoseidonHash as Hasher<BF>>::hash_pad(elements)
    }
    
    #[inline]
    fn q_two_to_one(left: BaseHashP2, right: BaseHashP2) -> BaseHashP2 {
        <PoseidonHash as Hasher<BF>>::two_to_one(left, right)
    }
}
impl<F: RichField> MerkleHasher<QHashOut<F>> for PoseidonHasher {
    #[inline]
    fn two_to_one(left: &QHashOut<F>, right: &QHashOut<F>) -> QHashOut<F> {
        QHashOut(<PoseidonHash as Hasher<F>>::two_to_one(left.0, right.0))
    }
}
impl MerkleHasher<BaseHashP2> for PoseidonHasher {
    #[inline]
    fn two_to_one(left: &BaseHashP2, right: &BaseHashP2) -> BaseHashP2 {
        <PoseidonHash as Hasher<BF>>::two_to_one(*left, *right)
    }
}

impl<F: RichField> MerkleHasher<QHashOut<F>> for PoseidonHash {
    #[inline]
    fn two_to_one(left: &QHashOut<F>, right: &QHashOut<F>) -> QHashOut<F> {
        QHashOut(<PoseidonHash as Hasher<F>>::two_to_one(left.0, right.0))
    }
}
impl MerkleHasher<BaseHashP2> for PoseidonHash {
    #[inline]
    fn two_to_one(left: &BaseHashP2, right: &BaseHashP2) -> BaseHashP2 {
        <PoseidonHash as Hasher<BF>>::two_to_one(*left, *right)
    }
}
/*
impl<F: Field, Hasher: FieldQHasher<F, QHashOut<F>>> MerkleHasher<QHashOut<F>> for Hasher {
    fn two_to_one(left: &QHashOut<F>, right: &QHashOut<F>) -> QHashOut<F> {
        <Hasher as FieldQHasher<F>>::q_two_to_one_ref(left, right)
    }
}

*/
impl MerkleZeroHasher<QHashOut<GoldilocksField>> for PoseidonHash {
    fn get_zero_hash(reverse_level: usize) -> QHashOut<GoldilocksField> {
        PoseidonHasher::get_zero_hash(reverse_level)
    }
}

impl MerkleZeroHasher<HashOut<GoldilocksField>> for PoseidonHash {
    fn get_zero_hash(reverse_level: usize) -> HashOut<GoldilocksField> {
        PoseidonHasher::get_zero_hash(reverse_level)
    }
}

impl QStaticNamedType for PoseidonHasher {
    fn q_static_type_name() -> &'static str {
        "PoseidonHasher"
    }
}

impl QFHasherU64<GoldilocksField, QHashOut<GoldilocksField>> for PoseidonHasher {}