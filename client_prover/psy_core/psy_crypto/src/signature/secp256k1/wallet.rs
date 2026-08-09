use std::collections::HashMap;

use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, VerifyingKey};
use plonky2::hash::{
    hash_types::RichField,
    hashing::{hash_n_to_hash_no_pad, PlonkyPermutation},
};
use psy_client_common::data::{
    base_types::{hash160::Hash160, hash256::Hash256},
    qhashout::QHashOut,
    secp256k1::{bytes_to_u32_vec_le, CompressedPublicKey},
};

use super::core::PsyCompressedSecp256K1Signature;
use crate::hash::core::btc::btc_hash160;

/// EIP-191 personal-sign domain separator, before the decimal message length.
pub const EIP191_MESSAGE_PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n";

/// EIP-191 prefix for the 32-byte sighashes bound by the signature circuit.
pub const EIP191_PREFIX_32: &[u8] = b"\x19Ethereum Signed Message:\n32";

/// Computes `keccak256("\x19Ethereum Signed Message:\n" || len || message)`.
///
/// The length is the message byte length encoded as ASCII decimal, as required
/// by EIP-191 and Ethereum `personal_sign`.
pub fn eth_personal_sign_digest(message: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};

    let message_len = message.len().to_string();
    let mut hasher = Keccak::v256();
    hasher.update(EIP191_MESSAGE_PREFIX);
    hasher.update(message_len.as_bytes());
    hasher.update(message);

    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    digest
}

fn canonical_compressed_public_key(verifying_key: &VerifyingKey) -> anyhow::Result<CompressedPublicKey> {
    let encoded = verifying_key.to_encoded_point(true);
    let bytes: [u8; 33] = encoded
        .as_bytes()
        .try_into()
        .map_err(|_| anyhow::format_err!("canonical secp256k1 public key length is not 33"))?;
    Ok(CompressedPublicKey(bytes))
}

pub fn validate_compressed_secp256k1_public_key(public_key: CompressedPublicKey) -> anyhow::Result<CompressedPublicKey> {
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key.0).map_err(|error| anyhow::anyhow!("invalid compressed secp256k1 public key: {error}"))?;
    let canonical = canonical_compressed_public_key(&verifying_key)?;
    anyhow::ensure!(canonical == public_key, "secp256k1 public key must use canonical compressed SEC1 encoding");
    Ok(canonical)
}

pub fn ethereum_address_for_verifying_key(verifying_key: &VerifyingKey) -> [u8; 20] {
    use tiny_keccak::{Hasher, Keccak};

    let encoded = verifying_key.to_encoded_point(false);
    let mut digest = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(&encoded.as_bytes()[1..]);
    hasher.finalize(&mut digest);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[12..]);
    address
}

pub fn eth_personal_registration_challenge(network_magic: u64, selected_address: [u8; 20]) -> Hash256 {
    use tiny_keccak::{Hasher, Keccak};

    let mut hasher = Keccak::v256();
    hasher.update(b"Psy external EIP-191 user registration\0");
    hasher.update(&network_magic.to_be_bytes());
    hasher.update(&selected_address);
    let mut challenge = [0u8; 32];
    hasher.finalize(&mut challenge);
    Hash256(challenge)
}

pub fn recover_eth_personal_signature(
    expected_address: [u8; 20],
    message: Hash256,
    signature_bytes: [u8; 65],
) -> anyhow::Result<PsyCompressedSecp256K1Signature> {
    anyhow::ensure!(expected_address.iter().any(|byte| *byte != 0), "selected Ethereum address must not be the zero address");
    let recovery_byte = match signature_bytes[64] {
        0 | 1 => signature_bytes[64],
        27 | 28 => signature_bytes[64] - 27,
        value => anyhow::bail!("unsupported Ethereum recovery id {value}; expected 0, 1, 27, or 28"),
    };
    let recovery_id = RecoveryId::from_byte(recovery_byte).ok_or_else(|| anyhow::anyhow!("invalid Ethereum recovery id {recovery_byte}"))?;
    let signature = Signature::from_slice(&signature_bytes[..64]).map_err(|error| anyhow::anyhow!("invalid Ethereum signature scalars: {error}"))?;
    anyhow::ensure!(signature.normalize_s().is_none(), "Ethereum signature must use canonical low-S form");

    let digest = eth_personal_sign_digest(&message.0);
    let verifying_key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .map_err(|error| anyhow::anyhow!("failed to recover Ethereum signer: {error}"))?;
    let actual_address = ethereum_address_for_verifying_key(&verifying_key);
    anyhow::ensure!(
        actual_address == expected_address,
        "Ethereum signature recovered address {}, expected {}",
        hex::encode(actual_address),
        hex::encode(expected_address)
    );

    Ok(PsyCompressedSecp256K1Signature {
        public_key: canonical_compressed_public_key(&verifying_key)?.0,
        signature: signature.to_bytes().into(),
        message,
    })
}

pub trait CompressedPublicKeyToP2PKH {
    fn to_p2pkh_address(&self) -> Hash160;
}
impl CompressedPublicKeyToP2PKH for CompressedPublicKey {
    fn to_p2pkh_address(&self) -> Hash160 {
        btc_hash160(&self.0)
    }
}
pub trait Secp256K1WalletProvider {
    fn sign(&self, public_key: &CompressedPublicKey, message: Hash256) -> anyhow::Result<PsyCompressedSecp256K1Signature>;
    fn sign_qhashout<F: RichField>(&self, public_key: &CompressedPublicKey, message: QHashOut<F>) -> anyhow::Result<PsyCompressedSecp256K1Signature>;
    fn contains_public_key(&self, public_key: &CompressedPublicKey) -> bool;
    fn contains_p2pkh_address(&self, p2pkh_address: &Hash160) -> bool;
    fn get_public_key_for_p2pkh(&self, p2pkh: &Hash160) -> Option<CompressedPublicKey>;
    fn get_public_keys(&self) -> Vec<CompressedPublicKey>;
}
#[derive(Debug, Clone)]
pub struct MemorySecp256K1Wallet {
    key_map: HashMap<CompressedPublicKey, k256::ecdsa::SigningKey>,
    p2pkh_key_map: HashMap<Hash160, CompressedPublicKey>,
}

impl Secp256K1WalletProvider for MemorySecp256K1Wallet {
    fn sign(&self, public_key: &CompressedPublicKey, message: Hash256) -> anyhow::Result<PsyCompressedSecp256K1Signature> {
        let private_key_result = self.key_map.get(public_key);
        if private_key_result.is_some() {
            let result: k256::ecdsa::Signature = private_key_result.unwrap().sign_prehash(&message.0)?;
            let mut rs_bytes = [0u8; 64];

            let r_bytes = result.r().to_bytes();
            let s_bytes = result.s().to_bytes();
            rs_bytes[0..32].copy_from_slice(&r_bytes);
            rs_bytes[32..64].copy_from_slice(&s_bytes);

            Ok(PsyCompressedSecp256K1Signature {
                public_key: public_key.0,
                signature: rs_bytes,
                message,
            })
        } else {
            anyhow::bail!("private key not found")
        }
    }

    fn sign_qhashout<F: RichField>(&self, public_key: &CompressedPublicKey, message: QHashOut<F>) -> anyhow::Result<PsyCompressedSecp256K1Signature> {
        let msg = message.to_le_bytes();
        let bytes: Hash256 = Hash256(msg);
        self.sign(public_key, bytes)
    }

    fn contains_public_key(&self, public_key: &CompressedPublicKey) -> bool {
        self.key_map.contains_key(public_key)
    }

    fn get_public_keys(&self) -> Vec<CompressedPublicKey> {
        self.key_map.keys().cloned().collect()
    }

    fn contains_p2pkh_address(&self, p2pkh_address: &Hash160) -> bool {
        self.p2pkh_key_map.contains_key(p2pkh_address)
    }

    fn get_public_key_for_p2pkh(&self, p2pkh: &Hash160) -> Option<CompressedPublicKey> {
        self.p2pkh_key_map.get(p2pkh).cloned()
    }
}

impl MemorySecp256K1Wallet {
    pub fn new() -> Self {
        Self {
            key_map: HashMap::new(),
            p2pkh_key_map: HashMap::new(),
        }
    }
    pub fn add_private_key(&mut self, private_key: Hash256) -> anyhow::Result<CompressedPublicKey> {
        let signing_key = k256::ecdsa::SigningKey::from_slice(&private_key.0)?;
        let pub_compressed = self.get_public_key(private_key)?;
        let p2pkh = pub_compressed.to_p2pkh_address();
        self.p2pkh_key_map.insert(p2pkh, pub_compressed);
        self.key_map.insert(pub_compressed, signing_key);
        Ok(pub_compressed)
    }

    pub fn get_public_key(&self, private_key: Hash256) -> anyhow::Result<CompressedPublicKey> {
        let signing_key = k256::ecdsa::SigningKey::from_slice(&private_key.0)?;
        let public_key = signing_key.verifying_key().to_encoded_point(true).to_bytes();
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

pub fn hash_no_pad_compressed_public_key<F: RichField, P: PlonkyPermutation<F>>(secp256k1_public_key: CompressedPublicKey) -> QHashOut<F> {
    let mut secp256k1_public_key_bytes = vec![secp256k1_public_key.0[0], 0, 0, 0];
    secp256k1_public_key_bytes.extend_from_slice(&secp256k1_public_key.0[1..]);
    let secp256k1_public_key_f = bytes_to_u32_vec_le(&secp256k1_public_key_bytes)
        .iter()
        .map(|n| F::from_canonical_u32(*n))
        .collect::<Vec<_>>();

    QHashOut(hash_n_to_hash_no_pad::<F, P>(&secp256k1_public_key_f))
}

pub fn get_secp_public_key<F: RichField>(private_key: QHashOut<F>) -> anyhow::Result<CompressedPublicKey> {
    let private_key = k256::ecdsa::SigningKey::from_slice(&Hash256::from(private_key).0)?;
    let public_key = private_key.verifying_key().to_encoded_point(true).to_bytes();
    let mut compressed = [0u8; 33];
    if public_key.len() == 33 {
        compressed.copy_from_slice(&public_key);
    } else {
        anyhow::bail!("public key length is not 33")
    }
    Ok(CompressedPublicKey(compressed))
}

/// Compresses either a SEC1 uncompressed public key (`0x04 || X || Y`) or a
/// raw coordinate pair (`X || Y`), as returned by Ethereum key recovery.
pub fn uncompressed_secp256k1_to_compressed(uncompressed: &[u8]) -> anyhow::Result<CompressedPublicKey> {
    let mut sec1_bytes = [0u8; 65];
    let encoded = if uncompressed.len() == 64 {
        sec1_bytes[0] = 0x04;
        sec1_bytes[1..].copy_from_slice(uncompressed);
        sec1_bytes.as_slice()
    } else {
        uncompressed
    };
    let verifying_key = VerifyingKey::from_sec1_bytes(encoded)
        .map_err(|error| anyhow::anyhow!("invalid uncompressed secp256k1 public key: {error}"))?;
    canonical_compressed_public_key(&verifying_key)
}

pub fn secp256k1_sign<F: RichField>(private_key: k256::ecdsa::SigningKey, sighash: QHashOut<F>) -> anyhow::Result<PsyCompressedSecp256K1Signature> {
    tracing::info!("🔔 prove_secp256k1_signature");

    let public_key = private_key.verifying_key().to_encoded_point(true).to_bytes();
    let mut compressed = [0u8; 33];
    if public_key.len() == 33 {
        compressed.copy_from_slice(&public_key);
    } else {
        return Err(anyhow::format_err!("pub key length is not 33"));
    }
    let pub_compressed = CompressedPublicKey(compressed);
    let result: k256::ecdsa::Signature = private_key.sign_prehash(&Hash256::from(sighash).0)?;
    let mut rs_bytes = [0u8; 64];

    let r_bytes = result.r().to_bytes();
    let s_bytes = result.s().to_bytes();
    rs_bytes[0..32].copy_from_slice(&r_bytes);
    rs_bytes[32..64].copy_from_slice(&s_bytes);

    Ok(PsyCompressedSecp256K1Signature {
        public_key: pub_compressed.0,
        signature: rs_bytes,
        message: sighash.into(),
    })
}

/// EIP-191 (`personal_sign`) counterpart of [`secp256k1_sign`]. Signs
/// `keccak256(EIP191_PREFIX_32 || raw_sighash_bytes)` — exactly what MetaMask
/// `personal_sign` produces over the raw sighash bytes — while storing the RAW
/// sighash in `message` so the circuit can re-derive the keccak in-circuit and
/// still bind the sighash into `combined_hash`.
pub fn secp256k1_sign_eth_personal<F: RichField>(private_key: k256::ecdsa::SigningKey, sighash: QHashOut<F>) -> anyhow::Result<PsyCompressedSecp256K1Signature> {
    tracing::info!("🔔 prove_eth_personal_secp256k1_signature");

    let public_key = private_key.verifying_key().to_encoded_point(true).to_bytes();
    let mut compressed = [0u8; 33];
    if public_key.len() == 33 {
        compressed.copy_from_slice(&public_key);
    } else {
        return Err(anyhow::format_err!("pub key length is not 33"));
    }
    let pub_compressed = CompressedPublicKey(compressed);

    let message = Hash256::from(sighash);
    let digest = eth_personal_sign_digest(&message.0);
    // k256's deterministic signer normalizes `s` to the low half of the curve
    // order, matching MetaMask's low-S output.
    let result: k256::ecdsa::Signature = private_key.sign_prehash(&digest)?;
    let mut rs_bytes = [0u8; 64];

    let r_bytes = result.r().to_bytes();
    let s_bytes = result.s().to_bytes();
    rs_bytes[0..32].copy_from_slice(&r_bytes);
    rs_bytes[32..64].copy_from_slice(&s_bytes);

    Ok(PsyCompressedSecp256K1Signature {
        public_key: pub_compressed.0,
        signature: rs_bytes,
        message,
    })
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::hash_types::HashOut,
    };
    use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut, secp256k1::CompressedPublicKey};

    use super::{
        eth_personal_registration_challenge, eth_personal_sign_digest,
        ethereum_address_for_verifying_key, recover_eth_personal_signature,
        secp256k1_sign_eth_personal, uncompressed_secp256k1_to_compressed,
        validate_compressed_secp256k1_public_key,
    };

    #[test]
    fn eip191_digest_uses_decimal_byte_length() {
        assert_eq!(
            hex::encode(eth_personal_sign_digest(b"hello")),
            "50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750"
        );
    }

    #[test]
    fn eip191_digest_matches_deterministic_32_byte_vector() {
        let message: [u8; 32] = core::array::from_fn(|index| index as u8);
        assert_eq!(
            hex::encode(eth_personal_sign_digest(&message)),
            "04c3a0e6f47dd8889a200887da01ab4fa88d85f15fb01537cd4b7bcc1ef6f991"
        );
    }

    #[test]
    fn registration_challenge_binds_network_and_address() {
        let address = [0x23; 20];
        let challenge = eth_personal_registration_challenge(42, address);
        assert_ne!(challenge, eth_personal_registration_challenge(43, address));
        let mut other_address = address;
        other_address[19] ^= 1;
        assert_ne!(challenge, eth_personal_registration_challenge(42, other_address));
    }

    #[test]
    fn eth_personal_signer_signs_the_stored_raw_message_digest() {
        let private_key = k256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let sighash = QHashOut(HashOut {
            elements: [
                GoldilocksField::from_canonical_u64(1),
                GoldilocksField::from_canonical_u64(2),
                GoldilocksField::from_canonical_u64(3),
                GoldilocksField::from_canonical_u64(4),
            ],
        });
        let signed = secp256k1_sign_eth_personal(private_key.clone(), sighash).unwrap();
        let expected_message = Hash256::from(sighash);
        assert_eq!(signed.message, expected_message);

        let signature = k256::ecdsa::Signature::from_slice(&signed.signature).unwrap();
        private_key
            .verifying_key()
            .verify_prehash(&eth_personal_sign_digest(&expected_message.0), &signature)
            .unwrap();
    }

    #[test]
    fn compresses_raw_and_sec1_public_keys_identically() {
        let signing_key = k256::ecdsa::SigningKey::from_slice(&[5u8; 32]).unwrap();
        let sec1 = signing_key.verifying_key().to_encoded_point(false);
        let raw: [u8; 64] = sec1.as_bytes()[1..].try_into().unwrap();

        let expected = uncompressed_secp256k1_to_compressed(&raw).unwrap();
        assert_eq!(expected, uncompressed_secp256k1_to_compressed(sec1.as_bytes()).unwrap());
        assert_eq!(expected.0.as_slice(), signing_key.verifying_key().to_encoded_point(true).as_bytes());
    }

    #[test]
    fn rejects_noncanonical_compressed_public_key_prefix() {
        let signing_key = k256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let encoded = signing_key.verifying_key().to_encoded_point(true);
        let mut public_key: [u8; 33] = encoded.as_bytes().try_into().unwrap();
        public_key[0] |= 0x80;
        assert!(validate_compressed_secp256k1_public_key(CompressedPublicKey(public_key)).is_err());
    }

    #[test]
    fn recovers_personal_signature_and_authenticates_address() {
        let signing_key = k256::ecdsa::SigningKey::from_slice(&[11u8; 32]).unwrap();
        let message = Hash256([0x42; 32]);
        let digest = eth_personal_sign_digest(&message.0);
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
        let expected_address = ethereum_address_for_verifying_key(signing_key.verifying_key());
        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(&signature.to_bytes());
        signature_bytes[64] = recovery_id.to_byte() + 27;

        let recovered = recover_eth_personal_signature(expected_address, message, signature_bytes).unwrap();
        assert_eq!(recovered.message, message);
        assert_eq!(recovered.signature, signature.to_bytes().as_slice());
        assert_eq!(recovered.public_key.as_slice(), signing_key.verifying_key().to_encoded_point(true).as_bytes());

        let mut wrong_address = expected_address;
        wrong_address[0] ^= 1;
        assert!(recover_eth_personal_signature(wrong_address, message, signature_bytes).is_err());
    }
}
