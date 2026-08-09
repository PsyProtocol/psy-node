//! `ExternalSecp256K1User` — the Mode-A (web/MetaMask) authorization signer.
//!
//! This is the EXTERNAL-SIGNATURE counterpart to [`SECP256K1User`]: instead of
//! holding a secp256k1 private key and signing the session sighash on demand,
//! it holds a *pre-computed* `PsyCompressedSecp256K1Signature` produced OUTSIDE
//! the SDK (e.g. by MetaMask `eth_sign`, which is byte-identical to a raw
//! `k256 sign_prehash` over the Psy sighash) and simply re-proves it through
//! the UNCHANGED secp256k1 authorization circuit.
//!
//! The two signers are interchangeable from the rest of the system's point of
//! view: both produce a `PsyProof` from `circuit_manager.prove_secp_sign(sig)`
//! that binds `hash(sighash, public_key_param)`, and both report the identical
//! `public_key_param` / `circuit_info`. The ONLY difference is the *source* of
//! the signature — held-key sign vs. an externally supplied one. This is what
//! lets the existing `WalletSession::sign_inner` dispatch authorize a contract
//! call with a MetaMask signature WITHOUT any circuit change.
//!
//! The signing private key never exists in the SDK for this user; it lives only
//! in MetaMask. The user is installed PK-first; once the session sighash is
//! known and MetaMask has signed it, the wallet entry is REPLACED by a
//! signature-carrying instance whose signature covers EXACTLY the sighash the
//! session computes (`UserProvingSessionManager::get_sighash(PSY_NETWORK_MAGIC,
//! nonce)`). `sign()` fails fast if no (or a stale) signature was injected.

use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonPermutation};
use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut, secp256k1::CompressedPublicKey};
use psy_client_data::config::store_config::{PsyPlonky2Config, PsyProof};
use psy_crypto::signature::{
    secp256k1::{
        core::PsyCompressedSecp256K1Signature,
        wallet::{hash_no_pad_compressed_public_key, validate_compressed_secp256k1_public_key},
    },
    zk::data::ZKPublicKeyInfo,
};
use psy_vm::ups::circuit_manager::UPSCircuitManager;

use crate::{
    signature::{
        context::SignContext,
        traits::{SignatureCircuitInfo, SignatureUser},
    },
    wallet::memory_wallet::PsyMemoryWallet,
};

pub(crate) fn validate_compressed_public_key(public_key: CompressedPublicKey) -> Result<CompressedPublicKey> {
    validate_compressed_secp256k1_public_key(public_key)
}

pub(crate) fn validate_signature_prehash(signature: &PsyCompressedSecp256K1Signature, prehash: &[u8; 32], label: &str) -> Result<()> {
    let verifying_key = VerifyingKey::from_sec1_bytes(&signature.public_key)
        .with_context(|| format!("{label} signature contains an invalid compressed public key"))?;
    let parsed = Signature::from_slice(&signature.signature).with_context(|| format!("{label} signature contains malformed r/s values"))?;
    ensure!(parsed.normalize_s().is_none(), "{label} signature must use canonical low-S form");
    verifying_key
        .verify_prehash(prehash, &parsed)
        .with_context(|| format!("{label} signature verification failed"))
}

/// A signature user backed by an externally produced secp256k1 signature
/// (Mode-A). Holds only the compressed public key plus, once injected, the
/// pre-signed `PsyCompressedSecp256K1Signature` over the session sighash.
///
/// Two-phase usage (PK-first):
/// 1. [`Self::new`] installs the user with ONLY the compressed public key —
///    enough for on-chain registration and trace generation.
/// 2. Once the session sighash is known and MetaMask has signed it, the wallet
///    entry is REPLACED by a signature-carrying user ([`Self::with_signature`],
///    via `PsyMemoryWallet::inject_secp_signature`).
#[derive(Debug, Clone)]
pub struct ExternalSecp256K1User {
    compressed_public_key: CompressedPublicKey,
    signature: Option<PsyCompressedSecp256K1Signature>,
}

impl ExternalSecp256K1User {
    /// PK-only form: no signature yet. Usable for on-chain registration and
    /// trace generation; `sign()` fails until a signature-carrying user is
    /// installed (see type-level docs).
    pub fn new(compressed_public_key: CompressedPublicKey) -> Result<Self> {
        Ok(Self {
            compressed_public_key: validate_compressed_public_key(compressed_public_key)?,
            signature: None,
        })
    }

    /// Full form: carries an externally produced signature (used for proving).
    pub fn with_signature(signature: PsyCompressedSecp256K1Signature) -> Result<Self> {
        validate_signature_prehash(&signature, &signature.message.0, "external secp256k1")?;
        Ok(Self {
            compressed_public_key: validate_compressed_public_key(CompressedPublicKey(signature.public_key))?,
            signature: Some(signature),
        })
    }

    /// The Poseidon `public_key_param` for this user, derived directly from the
    /// compressed public key. This is the SAME derivation
    /// `SECP256K1User::public_key_info` performs from the held key
    /// (`hash_no_pad_compressed_public_key`), so the resulting `pk_hash` and
    /// the end-cap `public_key_param` binding are byte-identical.
    fn public_key_param(&self) -> QHashOut<GoldilocksField> {
        hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(self.compressed_public_key)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureUser for ExternalSecp256K1User {
    async fn public_key_info(
        &self,
        _wallet: &PsyMemoryWallet,
        circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
    ) -> Result<ZKPublicKeyInfo<GoldilocksField>> {
        let public_key_param = self.public_key_param();
        let fingerprint = circuit_manager.secp_circuit_fingerprint().await?;
        Ok(ZKPublicKeyInfo {
            fingerprint,
            public_key_param,
        })
    }

    async fn sign(
        &self,
        _wallet: &PsyMemoryWallet,
        circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
        _context: &SignContext,
        sighash: QHashOut<GoldilocksField>,
    ) -> Result<PsyProof> {
        // Mode-A: do NOT sign here — the signature was produced externally
        // (MetaMask) over the session sighash and injected after trace
        // generation. Re-prove it through the UNCHANGED secp256k1 circuit.
        // Fail fast with a clear error if no (or a stale) signature was
        // injected — the circuit would reject it anyway, but opaquely.
        let signature = self.signature.as_ref().context(
            "external secp256k1 signature missing: generate the trace, sign its exact sig_hash, then inject the signature before proving",
        )?;
        let expected_message = Hash256::from(sighash);
        ensure!(
            signature.message == expected_message,
            "external secp256k1 signature message does not match session sighash: signed={}, expected={}",
            hex::encode(signature.message.0),
            hex::encode(expected_message.0)
        );
        validate_signature_prehash(signature, &expected_message.0, "external secp256k1")?;
        circuit_manager.prove_secp_sign(*signature).await
    }

    async fn circuit_info(
        &self,
        _wallet: &PsyMemoryWallet,
        circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
        _context: &SignContext,
    ) -> Result<SignatureCircuitInfo> {
        Ok(SignatureCircuitInfo {
            circuit_fingerprint: circuit_manager.secp_circuit_fingerprint().await?,
            verifier_config: circuit_manager.secp_circuit_verifier_config().await?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_external_signature() {
        let malformed = PsyCompressedSecp256K1Signature {
            public_key: [0; 33],
            signature: [0; 64],
            message: Hash256([7; 32]),
        };
        assert!(ExternalSecp256K1User::with_signature(malformed).is_err());
    }
}
