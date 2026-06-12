use tiny_keccak::{Hasher as _, Keccak};

use parth_core::{
    crypto::hash::traits::{BasicBytesHasher, BasicDataHasher, FieldQHasher, MerkleHasher, MerkleZeroHasher},
    data::hash::hash256::Hash256,
    generic_traits::QStaticNamedType,
    protocol::core_types::{BridgeHasherBase, QFHasherU64},
};

#[derive(Debug, Clone, Default)]
pub struct CoreKeccak256Hasher;

impl CoreKeccak256Hasher {
    #[inline]
    pub fn hash_bytes_inner(bytes: &[u8]) -> Hash256 {
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(bytes);
        hasher.finalize(&mut output);
        Hash256(output)
    }

    #[inline]
    pub fn hash_u64s_inner(data: &[u64]) -> Hash256 {
        let mut buffer = Vec::with_capacity(data.len() * 8);
        for value in data {
            buffer.extend_from_slice(&value.to_le_bytes());
        }
        Self::hash_bytes_inner(&buffer)
    }
}

impl MerkleHasher<Hash256> for CoreKeccak256Hasher {
    fn two_to_one(left: &Hash256, right: &Hash256) -> Hash256 {
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&left.0);
        input[32..].copy_from_slice(&right.0);
        Self::hash_bytes_inner(&input)
    }
}

impl MerkleZeroHasher<Hash256> for CoreKeccak256Hasher {
    fn get_zero_hash(reverse_level: usize) -> Hash256 {
        let mut current = Hash256::ZERO;
        for _ in 0..reverse_level {
            current = Self::two_to_one(&current, &current);
        }
        current
    }
}

impl BasicDataHasher<&[u8], Hash256> for CoreKeccak256Hasher {
    fn hash_data(data: &[u8]) -> Hash256 {
        Self::hash_bytes_inner(data)
    }
}

impl BasicBytesHasher<Hash256> for CoreKeccak256Hasher {
    fn hash_bytes(data: &[u8]) -> Hash256 {
        Self::hash_bytes_inner(data)
    }
}

impl FieldQHasher<u64, Hash256> for CoreKeccak256Hasher {
    fn q_hash_many(elements: &[u64]) -> Hash256 {
        Self::hash_u64s_inner(elements)
    }

    fn q_hash_many_pad(elements: &[u64]) -> Hash256 {
        let mut padded = elements.to_vec();
        let pad_len = (64 - (elements.len() % 64)) % 64;
        padded.resize(elements.len() + pad_len, 0u64);
        Self::hash_u64s_inner(&padded)
    }

    fn q_two_to_one(left: Hash256, right: Hash256) -> Hash256 {
        Self::q_two_to_one_ref(&left, &right)
    }

    fn q_two_to_one_ref(left: &Hash256, right: &Hash256) -> Hash256 {
        Self::two_to_one(left, right)
    }
}

impl QStaticNamedType for CoreKeccak256Hasher {
    fn q_static_type_name() -> &'static str {
        "CoreKeccak256Hasher"
    }
}

impl QFHasherU64<u64, Hash256> for CoreKeccak256Hasher {}
impl BridgeHasherBase<Hash256> for CoreKeccak256Hasher {}
