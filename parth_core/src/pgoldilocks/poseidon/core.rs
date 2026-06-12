
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
#[derive(Debug, Clone, Copy)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::felt::ToU64Value;
    use plonky2::field::types::Field;

    #[test]
    fn print_poseidon_reference_values() {
        let hash: BaseHashQ = PoseidonHasher::q_hash_many(&[
            GoldilocksField::from_canonical_u64(1),
            GoldilocksField::from_canonical_u64(2),
            GoldilocksField::from_canonical_u64(3),
            GoldilocksField::from_canonical_u64(4),
        ]);
        println!(
            "hash_no_pad(1,2,3,4)={:?}",
            hash.0
                .elements
                .iter()
                .map(|x| x.to_u64_value())
                .collect::<Vec<_>>()
        );

        let left = QHashOut(HashOut {
            elements: [
                GoldilocksField::from_canonical_u64(1),
                GoldilocksField::from_canonical_u64(2),
                GoldilocksField::from_canonical_u64(3),
                GoldilocksField::from_canonical_u64(4),
            ],
        });
        let right = QHashOut(HashOut {
            elements: [
                GoldilocksField::from_canonical_u64(5),
                GoldilocksField::from_canonical_u64(6),
                GoldilocksField::from_canonical_u64(7),
                GoldilocksField::from_canonical_u64(8),
            ],
        });
        let two: BaseHashQ = PoseidonHasher::q_two_to_one(left, right);
        println!(
            "two_to_one([1,2,3,4],[5,6,7,8])={:?}",
            two.0
                .elements
                .iter()
                .map(|x| x.to_u64_value())
                .collect::<Vec<_>>()
        );

        let mut current = QHashOut(HashOut {
            elements: [
                GoldilocksField::from_canonical_u64(0x59aa2f0f2c6d2e9d),
                GoldilocksField::from_canonical_u64(0x103c7e69c74ae9d6),
                GoldilocksField::from_canonical_u64(0xc388f9c7866e4b27),
                GoldilocksField::from_canonical_u64(0x12d83155d1c93dc6),
            ],
        });
        let mut zero = QHashOut(HashOut {
            elements: [
                GoldilocksField::ZERO,
                GoldilocksField::ZERO,
                GoldilocksField::ZERO,
                GoldilocksField::ZERO,
            ],
        });
        for depth in 0..=32 {
            let words: Vec<u64> = current.0.elements.iter().map(|x| x.to_u64_value()).collect();
            println!("leaf_fold_depth_{depth}={words:?}");
            current = PoseidonHasher::q_two_to_one(current, zero);
            zero = PoseidonHasher::q_two_to_one(zero, zero);
        }
    }
}
