use k256::ecdsa::{signature::hazmat::{PrehashSigner, PrehashVerifier}, Signature, VerifyingKey};

use std::collections::HashMap;

use rand::RngCore;

use crate::common::data::core::{hash::hash256::Hash256, secp256k1::{QPCompressedSecp256K1SignatureFull, QPSecp256K1Signature, QPSecp256K1CompressedPublicKey}};


pub trait Secp256K1WalletProvider {
    fn sign_hash(&self, public_key: &QPSecp256K1CompressedPublicKey, message: Hash256) -> anyhow::Result<QPCompressedSecp256K1SignatureFull>;
    fn contains_public_key(&self, public_key: &QPSecp256K1CompressedPublicKey) -> bool;
    fn get_public_keys(&self) -> Vec<QPSecp256K1CompressedPublicKey>;
}
#[derive(Debug, Clone)]
pub struct MemorySecp256K1Wallet {
    key_map: HashMap<QPSecp256K1CompressedPublicKey, k256::ecdsa::SigningKey>,
}

pub fn sign_hash_secp256k1_simple(private_key: &[u8; 32], hash: &[u8; 32]) -> anyhow::Result<[u8; 64]> {
    let signing_key = k256::ecdsa::SigningKey::from_slice(private_key)?;

    let result: k256::ecdsa::Signature = signing_key.sign_prehash(hash)?;
    let mut rs_bytes = [0u8; 64];

    let r_bytes = result.r().to_bytes();
    let s_bytes = result.s().to_bytes();
    rs_bytes[0..32].copy_from_slice(&r_bytes);
    rs_bytes[32..64].copy_from_slice(&s_bytes);

    Ok(rs_bytes)
}

impl Secp256K1WalletProvider for MemorySecp256K1Wallet {
    fn sign_hash(&self, public_key: &QPSecp256K1CompressedPublicKey, message: Hash256) -> anyhow::Result<QPCompressedSecp256K1SignatureFull> {
        let private_key_result = self.key_map.get(public_key);
        if private_key_result.is_some() {
            let result: k256::ecdsa::Signature = private_key_result.unwrap().sign_prehash(&message.0)?;
            let mut rs_bytes = [0u8; 64];

            let r_bytes = result.r().to_bytes();
            let s_bytes = result.s().to_bytes();
            rs_bytes[0..32].copy_from_slice(&r_bytes);
            rs_bytes[32..64].copy_from_slice(&s_bytes);

            Ok(QPCompressedSecp256K1SignatureFull {
                public_key: QPSecp256K1CompressedPublicKey(public_key.0),
                signature: QPSecp256K1Signature(rs_bytes),
                message,
            })
        } else {
            anyhow::bail!("private key not found")
        }
    }

    fn contains_public_key(&self, public_key: &QPSecp256K1CompressedPublicKey) -> bool {
        self.key_map.contains_key(public_key)
    }

    fn get_public_keys(&self) -> Vec<QPSecp256K1CompressedPublicKey> {
        self.key_map.keys().cloned().collect()
    }
}

impl MemorySecp256K1Wallet {
    pub fn new() -> Self {
        Self { key_map: HashMap::new() }
    }
    pub fn add_random_private_key(&mut self) -> anyhow::Result<(Hash256, QPSecp256K1CompressedPublicKey)> {
        let mut private_key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut private_key_bytes);
        let public_key = self.add_private_key(Hash256(private_key_bytes))?;

        Ok((Hash256(private_key_bytes), public_key))
    }
    pub fn add_private_key(&mut self, private_key: Hash256) -> anyhow::Result<QPSecp256K1CompressedPublicKey> {
        let signing_key = k256::ecdsa::SigningKey::from_slice(&private_key.0)?;
        let pub_compressed = self.get_public_key(private_key)?;
        self.key_map.insert(pub_compressed, signing_key);
        Ok(pub_compressed)
    }

    pub fn get_public_key(&self, private_key: Hash256) -> anyhow::Result<QPSecp256K1CompressedPublicKey> {
        let signing_key = k256::ecdsa::SigningKey::from_slice(&private_key.0)?;
        let public_key = signing_key.verifying_key().to_encoded_point(true).to_bytes();
        let mut compressed = [0u8; 33];
        if public_key.len() == 33 {
            compressed.copy_from_slice(&public_key);
        } else {
            anyhow::bail!("public key length is not 33")
        }
        let pub_compressed = QPSecp256K1CompressedPublicKey(compressed);
        Ok(pub_compressed)
    }

    pub fn get_private_key(&self, public_key: QPSecp256K1CompressedPublicKey) -> anyhow::Result<k256::ecdsa::SigningKey> {
        self.key_map.get(&public_key).cloned().ok_or(anyhow::format_err!("private key not found"))
    }
}

pub fn verify_secp256k1_signature(
    public_key: &QPSecp256K1CompressedPublicKey,
    message_hash: &Hash256,
    signature: &QPSecp256K1Signature,
) -> bool {
    let verifying_key = match VerifyingKey::from_sec1_bytes(&public_key.0) {
        Ok(key) => key,
        Err(_) => return false,
    };

    let signature_to_verify = match Signature::try_from(signature.0.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    verifying_key.verify_prehash(&message_hash.0, &signature_to_verify).is_ok()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_signature() {
        // 1. Setup: Create a wallet and generate a new key pair.
        let mut wallet = MemorySecp256K1Wallet::new();
        let (_private_key, public_key) = wallet.add_random_private_key().unwrap();

        // 2. Sign: Create a message hash and sign it.
        let message_hash = Hash256([1; 32]);
        let signature_full = wallet.sign_hash(&public_key, message_hash).unwrap();
        let signature = signature_full.signature;

        // 3. Test Valid Signature: Verify the signature with the correct data.
        // It should return true.
        assert!(
            verify_secp256k1_signature(&public_key, &message_hash, &signature),
            "Signature should be valid"
        );

        // 4. Test Invalid Signature: Tamper with the signature and verify again.
        // It should return false.
        let mut invalid_signature_bytes = signature.0;
        invalid_signature_bytes[0] = invalid_signature_bytes[0].wrapping_add(1); // Change one byte
        let invalid_signature = QPSecp256K1Signature(invalid_signature_bytes);
        assert!(
            !verify_secp256k1_signature(&public_key, &message_hash, &invalid_signature),
            "Tampered signature should be invalid"
        );

        // 5. Test Invalid Message Hash: Use a different message hash with the original signature.
        // It should return false.
        let wrong_message_hash = Hash256([2; 32]);
        assert!(
            !verify_secp256k1_signature(&public_key, &wrong_message_hash, &signature),
            "Signature should be invalid for a different message hash"
        );
    }
}