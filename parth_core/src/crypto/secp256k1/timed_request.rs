use crate::{crypto::hash::traits::BasicBytesHasher, data::hash::hash256::Hash256};

#[pderive::serialize_copy_ts_export]
pub struct SimpleTimedRequest {
    pub for_target: u64,
    pub request_type: u64,
    pub valid_until: u64,
    pub nonce: u64,
    pub tag: [u8; 32],
}

impl SimpleTimedRequest {
    pub fn get_sig_hash<Hasher: BasicBytesHasher<Hash256>>(&self) -> Hash256 {
        let mut bytes = [0u8; 64];
        bytes[0..8].copy_from_slice(&self.for_target.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.request_type.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.valid_until.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.nonce.to_le_bytes());
        bytes[32..64].copy_from_slice(&self.tag);
        Hasher::hash_bytes(&bytes)
    }
}