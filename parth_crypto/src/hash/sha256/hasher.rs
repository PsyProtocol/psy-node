use sha2::{Digest, Sha256};

use parth_core::{crypto::hash::traits::{BasicBytesHasher, BasicDataHasher, FieldQHasher, MerkleHasher}, data::hash::hash256::Hash256, generic_traits::QStaticNamedType, protocol::core_types::QFHasherU64};



#[derive(Debug, Clone)]
pub struct CoreSha256Hasher {
    hasher: Sha256,
}

impl CoreSha256Hasher {
    pub fn hash_bytes(bytes: &[u8]) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        Hash256(result.into())
    }
    pub fn hash_u64s(data: &[u64]) -> Hash256 {
        let mut hasher = Sha256::new();
        for d in data {
            hasher.update(u64::to_le_bytes(*d));

        }
        let result = hasher.finalize();
        Hash256(result.into())
    }
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }
    pub fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }
    pub fn finalize(self) -> Hash256 {
        let result = self.hasher.finalize();
        Hash256(result.into())
    }
    pub fn finalize_reset(&mut self) -> Hash256 {
        let result = self.hasher.finalize_reset();
        Hash256(result.into())
    }
}

impl MerkleHasher<Hash256> for CoreSha256Hasher {
    fn two_to_one(left: &Hash256, right: &Hash256) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(left.0);
        hasher.update(right.0);
        let result = hasher.finalize();
        Hash256(result.into())
    }
}


impl BasicDataHasher<&[u8], Hash256> for CoreSha256Hasher {
    fn hash_data(data: &[u8]) -> Hash256 {
        Self::hash_bytes(data)
    }
}
impl BasicBytesHasher<Hash256> for CoreSha256Hasher {
    fn hash_bytes(data: &[u8]) -> Hash256 {
        Self::hash_bytes(data)
    }
}

impl FieldQHasher<u64, Hash256> for CoreSha256Hasher {
    fn q_hash_many(elements: &[u64]) -> Hash256 {
        Self::hash_u64s(elements)
    }
    fn q_hash_many_pad(elements: &[u64]) -> Hash256 {
        let mut padded = elements.to_vec();
        let pad_len = (64 - (elements.len() % 64)) % 64;
        padded.extend(vec![0u64; pad_len]);
        Self::hash_u64s(&padded)
    }
    fn q_two_to_one(left: Hash256, right: Hash256) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(left.0);
        hasher.update(right.0);
        let result = hasher.finalize();
        Hash256(result.into())
    }
    fn q_two_to_one_ref(left: &Hash256, right: &Hash256) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(left.0);
        hasher.update(right.0);
        let result = hasher.finalize();
        Hash256(result.into())
    }
}

impl QStaticNamedType for CoreSha256Hasher {
    fn q_static_type_name() -> &'static str {
        "CoreSha256Hasher"
    }
}
impl QFHasherU64<u64, Hash256> for CoreSha256Hasher {}