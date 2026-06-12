use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::PoseidonHash,
    },
    iop::target::BoolTarget,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
    util::log2_ceil,
};
use psy_client_common::data::{
    base_types::{hash160::Hash160, hash192::Hash192, hash256::Hash256},
    qhashout::QHashOut,
};

use crate::field::qfield::QRichField;

pub trait QHasher<F: RichField> {
    fn q_two_to_one(left: QHashOut<F>, right: QHashOut<F>) -> QHashOut<F>;
}
pub trait ZeroableHash: Sized + Copy + Clone {
    fn get_zero_value() -> Self;
}
impl<F: Field> ZeroableHash for HashOut<F> {
    fn get_zero_value() -> Self {
        HashOut::<F>::ZERO
    }
}
impl ZeroableHash for Hash256 {
    fn get_zero_value() -> Self {
        Self([0u8; 32])
    }
}

impl ZeroableHash for Hash192 {
    fn get_zero_value() -> Self {
        Self([0u8; 24])
    }
}

impl ZeroableHash for Hash160 {
    fn get_zero_value() -> Self {
        Self([0u8; 20])
    }
}
impl<F: Field> ZeroableHash for QHashOut<F> {
    fn get_zero_value() -> Self {
        QHashOut(HashOut::<F>::ZERO)
    }
}
pub trait MerkleHasher<Hash: PartialEq> {
    fn two_to_one(left: &Hash, right: &Hash) -> Hash;
    fn two_to_one_swap(swap: bool, left: &Hash, right: &Hash) -> Hash {
        if swap {
            Self::two_to_one(right, left)
        } else {
            Self::two_to_one(left, right)
        }
    }
}

pub trait MerkleLeafHasher<Hash: PartialEq + Copy> {
    fn compute_root_from_leaves(leaves: &[Hash]) -> anyhow::Result<Hash>;
}

impl<Hash: PartialEq + Copy, H: MerkleHasher<Hash>> MerkleLeafHasher<Hash> for H {
    fn compute_root_from_leaves(leaves: &[Hash]) -> anyhow::Result<Hash> {
        let leaves_len = leaves.len();
        if leaves_len == 0 {
            anyhow::bail!("compute_root_from_leaves called with an empty array");
        } else if leaves_len == 1 {
            return Ok(leaves[0]);
        } else if leaves_len == 2 {
            return Ok(Self::two_to_one(&leaves[0], &leaves[1]));
        }

        let height = log2_ceil(leaves_len);
        if leaves_len != (1usize << height) {
            anyhow::bail!("compute_root_from_leaves called where leaves.len() is not a power of 2");
        } else {
            let mut current_leaves_len = leaves_len >> 1;
            let mut current_leaves = Vec::with_capacity(current_leaves_len);
            for i in 0..current_leaves_len {
                current_leaves.push(Self::two_to_one(&leaves[i * 2], &leaves[i * 2 + 1]));
            }

            while current_leaves_len > 1 {
                let level_leaves_len = current_leaves_len >> 1;
                let mut level_leaves = Vec::with_capacity(level_leaves_len);

                for i in 0..level_leaves_len {
                    level_leaves.push(Self::two_to_one(&current_leaves[i * 2], &current_leaves[i * 2 + 1]));
                }

                current_leaves = level_leaves;
                current_leaves_len = level_leaves_len;
            }

            Ok(current_leaves[0])
        }
    }
}
pub trait MerkleHasherWithMarkedLeaf<Hash: PartialEq>: MerkleHasher<Hash> {
    fn two_to_one_marked_leaf(left: &Hash, right: &Hash) -> Hash;
    fn two_to_one_marked_leaf_swap(swap: bool, left: &Hash, right: &Hash) -> Hash {
        if swap {
            Self::two_to_one_marked_leaf(right, left)
        } else {
            Self::two_to_one_marked_leaf(left, right)
        }
    }
}

pub trait MerkleZeroHasher<Hash: PartialEq>: MerkleHasher<Hash> {
    fn get_zero_hash(reverse_level: usize) -> Hash;
}
pub trait MerkleZeroHasherWithMarkedLeaf<Hash: PartialEq>: MerkleZeroHasher<Hash> + MerkleHasherWithMarkedLeaf<Hash> {
    fn get_zero_hash_marked(reverse_level: usize) -> Hash;
}

pub const ZERO_HASH_CACHE_SIZE: usize = 128;
pub trait MerkleZeroHasherWithCache<Hash: PartialEq + Copy>: MerkleHasher<Hash> {
    const CACHED_ZERO_HASHES: [Hash; ZERO_HASH_CACHE_SIZE];
}
pub trait MerkleZeroHasherWithCacheMarkedLeaf<Hash: PartialEq + Copy>: MerkleHasherWithMarkedLeaf<Hash> {
    const CACHED_MARKED_LEAF_ZERO_HASHES: [Hash; ZERO_HASH_CACHE_SIZE];
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

impl<F: RichField> BasicFieldHasher<F> for PoseidonHash {
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

impl<H: FieldQHasher<F>, F: RichField> MerkleHasher<HashOut<F>> for H {
    fn two_to_one(left: &HashOut<F>, right: &HashOut<F>) -> HashOut<F> {
        <H as FieldQHasher<F>>::two_to_one(*left, *right)
    }
}
impl<H: FieldQHasher<F>, F: RichField> MerkleHasher<QHashOut<F>> for H {
    fn two_to_one(left: &QHashOut<F>, right: &QHashOut<F>) -> QHashOut<F> {
        <H as FieldQHasher<F>>::q_two_to_one(*left, *right)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PoseidonHasher;

impl<F: RichField> Hasher<F> for PoseidonHasher {
    const HASH_SIZE: usize = <PoseidonHash as Hasher<F>>::HASH_SIZE;

    type Hash = HashOut<F>;
    type Permutation = <PoseidonHash as Hasher<F>>::Permutation;

    fn hash_no_pad(input: &[F]) -> Self::Hash {
        PoseidonHash::hash_no_pad(input)
    }

    fn hash_pad(input: &[F]) -> Self::Hash {
        PoseidonHash::hash_pad(input)
    }

    fn two_to_one(left: Self::Hash, right: Self::Hash) -> Self::Hash {
        <PoseidonHash as Hasher<F>>::two_to_one(left, right)
    }
}

impl<F: RichField> AlgebraicHasher<F> for PoseidonHasher {
    type AlgebraicPermutation = <PoseidonHash as AlgebraicHasher<F>>::AlgebraicPermutation;

    fn permute_swapped<const D: usize>(
        inputs: Self::AlgebraicPermutation,
        swap: BoolTarget,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::AlgebraicPermutation
    where
        F: RichField + Extendable<D>,
    {
        <PoseidonHash as AlgebraicHasher<F>>::permute_swapped(inputs, swap, builder)
    }
}
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
impl<F: QRichField> MerkleHasherWithMarkedLeaf<HashOut<F>> for PoseidonHasher {
    fn two_to_one_marked_leaf(left: &HashOut<F>, right: &HashOut<F>) -> HashOut<F> {
        PoseidonHash::hash_no_pad(&[
            left.elements[0],
            left.elements[1],
            left.elements[2],
            left.elements[3],
            right.elements[0],
            right.elements[1],
            right.elements[2],
            right.elements[3],
            F::ONE,
        ])
    }
}

impl<F: QRichField> MerkleHasherWithMarkedLeaf<QHashOut<F>> for PoseidonHasher {
    fn two_to_one_marked_leaf(left: &QHashOut<F>, right: &QHashOut<F>) -> QHashOut<F> {
        QHashOut(PoseidonHash::hash_no_pad(&[
            left.0.elements[0],
            left.0.elements[1],
            left.0.elements[2],
            left.0.elements[3],
            right.0.elements[0],
            right.0.elements[1],
            right.0.elements[2],
            right.0.elements[3],
            F::ONE,
        ]))
    }
}

impl<F: QRichField> MerkleHasherWithMarkedLeaf<QHashOut<F>> for PoseidonHash {
    fn two_to_one_marked_leaf(left: &QHashOut<F>, right: &QHashOut<F>) -> QHashOut<F> {
        QHashOut(PoseidonHash::hash_no_pad(&[
            left.0.elements[0],
            left.0.elements[1],
            left.0.elements[2],
            left.0.elements[3],
            right.0.elements[0],
            right.0.elements[1],
            right.0.elements[2],
            right.0.elements[3],
            F::ONE,
        ]))
    }
}
impl<F: QRichField> MerkleHasherWithMarkedLeaf<HashOut<F>> for PoseidonHash {
    fn two_to_one_marked_leaf(left: &HashOut<F>, right: &HashOut<F>) -> HashOut<F> {
        PoseidonHash::hash_no_pad(&[
            left.elements[0],
            left.elements[1],
            left.elements[2],
            left.elements[3],
            right.elements[0],
            right.elements[1],
            right.elements[2],
            right.elements[3],
            F::ONE,
        ])
    }
}

impl<Hash: PartialEq + Copy, T: MerkleZeroHasherWithCache<Hash> + MerkleZeroHasherWithCacheMarkedLeaf<Hash>> MerkleZeroHasherWithMarkedLeaf<Hash>
    for T
{
    fn get_zero_hash_marked(reverse_level: usize) -> Hash {
        if reverse_level < ZERO_HASH_CACHE_SIZE {
            T::CACHED_MARKED_LEAF_ZERO_HASHES[reverse_level]
        } else {
            let current = T::CACHED_MARKED_LEAF_ZERO_HASHES[ZERO_HASH_CACHE_SIZE - 1];
            iterate_merkle_hasher::<Hash, Self>(current, reverse_level - ZERO_HASH_CACHE_SIZE + 1)
        }
    }
}

impl MerkleZeroHasherWithMarkedLeaf<QHashOut<GoldilocksField>> for PoseidonHash {
    fn get_zero_hash_marked(reverse_level: usize) -> QHashOut<GoldilocksField> {
        PoseidonHasher::get_zero_hash_marked(reverse_level)
    }
}
impl MerkleZeroHasher<QHashOut<GoldilocksField>> for PoseidonHash {
    fn get_zero_hash(reverse_level: usize) -> QHashOut<GoldilocksField> {
        PoseidonHasher::get_zero_hash(reverse_level)
    }
}

impl MerkleZeroHasherWithMarkedLeaf<HashOut<GoldilocksField>> for PoseidonHash {
    fn get_zero_hash_marked(reverse_level: usize) -> HashOut<GoldilocksField> {
        <PoseidonHash as MerkleZeroHasherWithMarkedLeaf<QHashOut<GoldilocksField>>>::get_zero_hash_marked(reverse_level).0
    }
}
impl MerkleZeroHasher<HashOut<GoldilocksField>> for PoseidonHash {
    fn get_zero_hash(reverse_level: usize) -> HashOut<GoldilocksField> {
        PoseidonHasher::get_zero_hash(reverse_level)
    }
}
/*
impl<F: RichField> FieldHasher<HashOut<F>, F> for PoseidonHash {
    fn hash_many(elements: &[F]) -> HashOut<F> {
        PoseidonHash::hash_no_pad(elements)
    }

    fn hash_many_pad(elements: &[F]) -> HashOut<F> {
        PoseidonHash::hash_pad(elements)
    }
}
impl<F: RichField> FieldQHasher<F> for PoseidonHash {
    fn hash_many(elements: &[F]) -> QHashOut<F> {
        QHashOut(PoseidonHash::hash_no_pad(elements))
    }

    fn hash_many_pad(elements: &[F]) -> QHashOut<F> {
        QHashOut(PoseidonHash::hash_pad(elements))
    }
}*/
/*
fn compute_zero_hashes_core<Hash: PartialEq + ZeroableHash + Copy, Hasher: MerkleHasher<Hash>, const N: usize>() -> [Hash; N] {
    let mut result = [Hash::get_zero_value(); N];

    for i in 1..N {
        result[i] = Hasher::two_to_one(&result[i-1], &result[i-1]);
    }
    result
}*/

/*
impl<F: RichField, H: Hasher<F, Hash = HashOut<F>>> FieldQHasher<F> for H {
    fn hash_many(elements: &[F]) -> QHashOut<F> {
        QHashOut(H::hash_no_pad(elements))
    }

    fn hash_many_pad(elements: &[F]) -> QHashOut<F> {
        QHashOut(H::hash_pad(elements))
    }
}
*/
pub fn iterate_merkle_hasher_alg<H: AlgebraicHasher<F>, F: RichField>(current: QHashOut<F>, reverse_level: usize) -> QHashOut<F> {
    let mut value = current.0;
    for _ in 0..reverse_level {
        value = H::two_to_one(value, value);
    }
    QHashOut(value)
}
pub fn iterate_merkle_hasher<Hash: PartialEq, Hasher: MerkleHasher<Hash>>(mut current: Hash, reverse_level: usize) -> Hash {
    for _ in 0..reverse_level {
        current = Hasher::two_to_one(&current, &current);
    }
    current
}
impl<Hash: PartialEq + Copy, T: MerkleZeroHasherWithCache<Hash>> MerkleZeroHasher<Hash> for T {
    fn get_zero_hash(reverse_level: usize) -> Hash {
        if reverse_level < ZERO_HASH_CACHE_SIZE {
            T::CACHED_ZERO_HASHES[reverse_level]
        } else {
            let current = T::CACHED_ZERO_HASHES[ZERO_HASH_CACHE_SIZE - 1];
            iterate_merkle_hasher::<Hash, Self>(current, reverse_level - ZERO_HASH_CACHE_SIZE + 1)
        }
    }
}

impl<F: RichField> QAlgebraicHasher<F> for PoseidonHasher {}
impl<F: RichField> QAlgebraicHasher<F> for PoseidonHash {}
