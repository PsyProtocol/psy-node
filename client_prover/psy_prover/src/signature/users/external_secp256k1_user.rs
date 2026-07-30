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

use anyhow::Result;
use async_trait::async_trait;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonPermutation};
use psy_client_common::data::{qhashout::QHashOut, secp256k1::CompressedPublicKey};
use psy_client_data::config::store_config::{PsyPlonky2Config, PsyProof};
use psy_crypto::signature::{
    secp256k1::{core::PsyCompressedSecp256K1Signature, wallet::hash_no_pad_compressed_public_key},
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
    pub fn new(compressed_public_key: CompressedPublicKey) -> Self {
        Self {
            compressed_public_key,
            signature: None,
        }
    }

    /// Full form: carries an externally produced signature (used for proving).
    pub fn with_signature(signature: PsyCompressedSecp256K1Signature) -> Self {
        Self {
            compressed_public_key: CompressedPublicKey(signature.public_key),
            signature: Some(signature),
        }
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
        let signature = self.signature.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "ExternalSecp256K1User has no signature yet: register the user PK-first, generate the trace, then inject a MetaMask signature over the session sighash before proving"
            )
        })?;
        let signed_sighash = QHashOut::from(signature.message);
        anyhow::ensure!(
            signed_sighash == sighash,
            "injected MetaMask signature is over message {} but the session sighash is {} — the signature must cover the exact session sighash",
            signed_sighash,
            sighash
        );
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
