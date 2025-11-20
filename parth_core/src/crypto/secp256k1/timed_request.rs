use crate::{crypto::{hash::traits::BasicBytesHasher, secp256k1::{CompressedPublicKey, QEDCompressedSecp256K1Signature, Secp256K1WalletProvider}}, data::hash::hash256::Hash256};

#[pderive::serialize_copy_ts_export]
pub struct SimpleTimedRequest {
    pub for_target: u64,
    pub request_type: u64,
    pub valid_until: u64,
    pub nonce: u64,
    pub tag: [u8; 32],
}

pub fn get_current_time_ms() -> u64 {
    let now = std::time::SystemTime::now();
    let since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap();
    since_epoch.as_millis() as u64
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
    pub fn create_signed_timed_request_for_request_proof_work<Signer: Secp256K1WalletProvider, Hasher: BasicBytesHasher<Hash256>>(signer: &Signer, compressed_public_key: &CompressedPublicKey, valid_duration_ms: u64, tag: [u8; 32]) -> (QEDCompressedSecp256K1Signature, Self) {
        let request = SimpleTimedRequest {
            for_target: 0,
            request_type: 1,
            valid_until: get_current_time_ms() + valid_duration_ms,
            nonce: 0,
            tag,
        };
        let sig_hash = request.get_sig_hash::<Hasher>();
        let signature = signer.sign(compressed_public_key, sig_hash).unwrap();
        (signature, request)
    }
}