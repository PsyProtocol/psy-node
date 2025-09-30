use parth_core::crypto::hash::{merkle_proof::iterate_merkle_hasher, traits::{MerkleHasher, MerkleZeroHasher}};
use sha3::{Digest, Keccak256};


#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeccakHasher;

impl MerkleHasher<[u8; 32]> for KeccakHasher {
    fn two_to_one(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }
}
/*
impl MerkleHasher<Hash256> for KeccakHasher {
    fn two_to_one(left: &Hash256, right: &Hash256) -> Hash256 {
        let mut hasher = Keccak256::new();
        hasher.update(left.0);
        hasher.update(right.0);
        Hash256(hasher.finalize().into())
    }
}
impl MerkleZeroHasher<Hash256> for KeccakHasher {
    fn get_zero_hash(reverse_level: usize) -> Hash256 {
        iterate_merkle_hasher::<Hash256, Self>(Hash256::ZERO, reverse_level)
    }
}*/

impl MerkleZeroHasher<[u8; 32]> for KeccakHasher {
    fn get_zero_hash(reverse_level: usize) -> [u8; 32] {
        iterate_merkle_hasher::<[u8; 32], Self>([0u8; 32], reverse_level)
    }
}
