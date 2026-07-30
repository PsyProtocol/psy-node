use std::collections::HashMap;

use k256::ecdsa::signature::hazmat::PrehashSigner;
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

/// The EIP-191 prefix for a 32-byte `personal_sign` message:
/// `0x19 || "Ethereum Signed Message:\n" || "32"` (28 bytes).
/// This is the single source of truth — the in-circuit keccak gadget
/// (`psy_common_circuit::crypto::secp256k1::gadget`) re-exports it so the
/// circuit preimage and the host-side signing preimage can never drift apart.
pub const EIP191_PREFIX_32: &[u8] = b"\x19Ethereum Signed Message:\n32";

/// Host-side EIP-191 digest: `keccak256(EIP191_PREFIX_32 || message)`.
/// `message` must be the exact 32 bytes the circuit binds as the raw sighash
/// (`Hash256::from(sighash).0`), matching what a MetaMask `personal_sign`
/// over those bytes would produce.
pub fn eth_personal_sign_digest(message: &[u8; 32]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};

    let mut hasher = Keccak::v256();
    hasher.update(EIP191_PREFIX_32);
    hasher.update(message);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    digest
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

/// Compresses an uncompressed secp256k1 public key — either the SEC1 form
/// (`0x04 || X || Y`, 65 bytes) or the raw coordinate pair (`X || Y`, 64
/// bytes), which is what MetaMask signature recovery (`ecrecover`) returns.
///
/// Compression is lossless: `0x02`/`0x03` prefix encodes the parity of Y,
/// followed by X. The circuit witnesses the full (x, y) anyway; the
/// compressed form is only the off-chain representation used for
/// `public_key_param` and registration.
pub fn uncompressed_secp256k1_to_compressed(uncompressed: &[u8]) -> anyhow::Result<CompressedPublicKey> {
    let coords: &[u8] = match uncompressed.len() {
        65 if uncompressed[0] == 0x04 => &uncompressed[1..],
        64 => uncompressed,
        _ => anyhow::bail!("expected 65-byte (0x04-prefixed) or 64-byte uncompressed secp256k1 public key, got {} bytes", uncompressed.len()),
    };
    let (x, y) = coords.split_at(32);
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02 | (y[31] & 1);
    compressed[1..].copy_from_slice(x);
    Ok(CompressedPublicKey(compressed))
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
