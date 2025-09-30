use crate::common::{data::core::hash::hash256::Hash256, utils::math::log2_ceil};

pub trait ZeroableHash: Sized + Copy + Clone {
    fn get_zero_value() -> Self;
}
impl ZeroableHash for Hash256 {
    fn get_zero_value() -> Self {
       Self([0u8; 32])
    }
}

pub trait MerkleHasher<Hash: PartialEq> {
    fn two_to_one(left: &Hash, right: &Hash) -> Hash;
    fn two_to_one_swap(swap: bool, left: &Hash, right: &Hash) -> Hash {
        if swap {
            Self::two_to_one(right, left)
        }else{
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
        }else if leaves_len == 1 {
            return Ok(leaves[0]);
        }else if leaves_len == 2{
            return Ok(Self::two_to_one(&leaves[0], &leaves[1]))
        }

        let height = log2_ceil(leaves_len);
        if leaves_len != (1usize<<height) {
            anyhow::bail!("compute_root_from_leaves called where leaves.len() is not a power of 2");
        }else{
            let mut current_leaves_len = leaves_len>>1;
            let mut current_leaves = Vec::with_capacity(current_leaves_len);
            for i in 0..current_leaves_len {
                current_leaves.push(Self::two_to_one(&leaves[i*2], &leaves[i*2+1]));
            }

            while current_leaves_len > 1 {
                let level_leaves_len = current_leaves_len >> 1;
                let mut level_leaves = Vec::with_capacity(level_leaves_len);

                for i in 0..level_leaves_len {
                    level_leaves.push(Self::two_to_one(&current_leaves[i*2], &current_leaves[i*2+1]));
                }

                current_leaves = level_leaves;
                current_leaves_len = level_leaves_len;
            }

            Ok(current_leaves[0])
        }
    }
}
pub trait MerkleZeroHasher<Hash: PartialEq>: MerkleHasher<Hash> {
    fn get_zero_hash(reverse_level: usize) -> Hash;
}

pub const ZERO_HASH_CACHE_SIZE: usize = 128;
pub trait MerkleZeroHasherWithCache<Hash: PartialEq + Copy>: MerkleHasher<Hash> {
    const CACHED_ZERO_HASHES: [Hash; ZERO_HASH_CACHE_SIZE];
}


pub trait BasicDataHasher<Data, Hash: PartialEq> {
    fn hash_data(data: Data) -> Hash;
}

pub trait BasicBytesHasher<Hash: PartialEq> {
    fn hash_bytes(data: &[u8]) -> Hash;
}


pub fn iterate_merkle_hasher<Hash: PartialEq, Hasher: MerkleHasher<Hash>>(
    mut current: Hash,
    reverse_level: usize,
) -> Hash {
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
