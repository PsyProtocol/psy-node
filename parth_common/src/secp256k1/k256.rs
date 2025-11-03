use std::collections::HashMap;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use parth_core::{crypto::secp256k1::{CompressedPublicKey, QEDCompressedSecp256K1Signature, Secp256K1Verifier, Secp256K1WalletProvider}, data::hash::hash256::Hash256};

use k256::ecdsa::{
    signature::hazmat::PrehashVerifier, Signature as K256Signature, VerifyingKey,
};

#[derive(Debug, Clone)]
pub struct MemorySecp256K1Wallet {
    key_map: HashMap<CompressedPublicKey, k256::ecdsa::SigningKey>,
}

impl Secp256K1WalletProvider for MemorySecp256K1Wallet {
    fn sign(
        &self,
        public_key: &CompressedPublicKey,
        message: Hash256,
    ) -> anyhow::Result<QEDCompressedSecp256K1Signature> {
        let private_key_result = self.key_map.get(public_key);
        if private_key_result.is_some() {
            let result: k256::ecdsa::Signature =
                private_key_result.unwrap().sign_prehash(&message.0)?;
            let mut rs_bytes = [0u8; 64];

            let r_bytes = result.r().to_bytes();
            let s_bytes = result.s().to_bytes();
            rs_bytes[0..32].copy_from_slice(&r_bytes);
            rs_bytes[32..64].copy_from_slice(&s_bytes);

            Ok(QEDCompressedSecp256K1Signature {
                public_key: public_key.0,
                signature: rs_bytes,
                message: message,
            })
        } else {
            anyhow::bail!("private key not found")
        }
    }

    fn contains_public_key(&self, public_key: &CompressedPublicKey) -> bool {
        self.key_map.contains_key(public_key)
    }

    fn get_public_keys(&self) -> Vec<CompressedPublicKey> {
        self.key_map.keys().cloned().collect()
    }

}

impl MemorySecp256K1Wallet {
    pub fn new() -> Self {
        Self {
            key_map: HashMap::new(),
        }
    }
    pub fn add_private_key(&mut self, private_key: Hash256) -> anyhow::Result<CompressedPublicKey> {
        let signing_key = k256::ecdsa::SigningKey::from_slice(&private_key.0)?;
        let pub_compressed = self.get_public_key(private_key)?;
        self.key_map.insert(pub_compressed, signing_key);
        Ok(pub_compressed)
    }

    pub fn get_public_key(&self, private_key: Hash256) -> anyhow::Result<CompressedPublicKey> {
        let signing_key = k256::ecdsa::SigningKey::from_slice(&private_key.0)?;
        let public_key = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .to_bytes();
        let mut compressed = [0u8; 33];
        if public_key.len() == 33 {
            compressed.copy_from_slice(&public_key);
        } else {
            anyhow::bail!("public key length is not 33")
        }
        let pub_compressed = CompressedPublicKey(compressed);
        Ok(pub_compressed)
    }

    pub fn get_private_key(&self, public_key: CompressedPublicKey) -> anyhow::Result<k256::ecdsa::SigningKey> {
        self.key_map.get(&public_key).cloned().ok_or(anyhow::format_err!("private key not found"))
    }
}



#[derive(Debug, Clone, Copy)]
pub struct Secp256K1VerifierHelper;

impl Secp256K1Verifier for Secp256K1VerifierHelper {
    fn secp256k1_verify(
        signature: &QEDCompressedSecp256K1Signature,
    ) -> anyhow::Result<()> {
        // Create a VerifyingKey from the compressed public key bytes.
        let verifying_key = VerifyingKey::from_sec1_bytes(&signature.public_key)
            .map_err(|e| anyhow::anyhow!("Failed to parse public key: {}", e))?;

        // Create a Signature from the raw 64-byte signature.
        let ecdsa_signature = K256Signature::from_slice(&signature.signature)
            .map_err(|e| anyhow::anyhow!("Failed to parse signature: {}", e))?;

        // The message is already a hash, so we use pre-hashed verification.
        if verifying_key
            .verify_prehash(&signature.message.0, &ecdsa_signature)
            .is_ok()
        {
            Ok(())
        } else {
            anyhow::bail!("Signature verification failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_sign_verify_round_trip() -> anyhow::Result<()> {
        let mut wallet = MemorySecp256K1Wallet::new();

        // Fixed private key from a secp256k1 test vector (hex: ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f)
        let private_key_bytes = hex!(
            "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f"
        );
        let private_key = Hash256(private_key_bytes);
        let pub_key = wallet.add_private_key(private_key)?;

        // Fixed message hash from the same test vector (hex: 4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a)
        let message_bytes = hex!(
            "4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a"
        );
        let message = Hash256(message_bytes);

        // Sign
        let sig = wallet.sign(&pub_key, message)?;

        // Verify
        Secp256K1VerifierHelper::secp256k1_verify(&sig)?;

        // Optional: Assert public key matches expected compressed form from vector
        let expected_pub_bytes = hex!(
            "02779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd"
        ); // 02 + x (y even)
        assert_eq!(pub_key.0, expected_pub_bytes);

        Ok(())
    }
}