//! `ExternalEthPersonalSignUser` — the Mode-A (web/MetaMask) authorization
//! signer for MetaMask `personal_sign` (EIP-191).
//!
//! This is the keccak-prefixed sibling of [`super::ExternalSecp256K1User`].
//! MetaMask removed raw `eth_sign`, so the only signing primitive a
//! self-custody MetaMask user can reach is `personal_sign`, which signs
//! `keccak256("\x19Ethereum Signed Message:\n32" || sighash)` rather than the
//! raw sighash. This signer therefore re-proves the supplied signature through
//! the EIP-191 circuit (`EthPersonalSignSecp256K1SignatureCircuit`), which
//! verifies the ECDSA over that keccak digest while binding the RAW sighash
//! into the end-cap's `public_inputs_hash` — preserving the operation binding
//! without touching the classic secp circuit.
//!
//! Like [`super::ExternalSecp256K1User`], NO private key is held in the SDK —
//! it lives only in MetaMask. The signature is supplied at construction (built
//! from the `personal_sign` output: compressed pubkey + low-S `(r,s)` + the raw
//! sighash as `message`). Because this user reports a DIFFERENT circuit
//! fingerprint than the classic secp user, the resulting `public_key` (and
//! hence `pk_hash` / `user_id`) is a DISTINCT Psy identity — a new signature
//! type, not a re-skin of the classic one.

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

/// A signature user backed by an externally produced MetaMask `personal_sign`
/// signature (Mode-A, EIP-191). Holds only the compressed public key plus,
/// once injected, the pre-signed `PsyCompressedSecp256K1Signature` — whose
/// `(r,s)` is over `keccak256(EIP-191 prefix || sighash)` and whose `message`
/// is the raw sighash.
///
/// Two-phase usage (PK-first):
/// 1. [`Self::new`] installs the user with ONLY the compressed public key —
///    enough for on-chain registration and trace generation.
/// 2. Once the session sighash is known and MetaMask has signed it, the wallet
///    entry is REPLACED by a signature-carrying user ([`Self::with_signature`],
///    via `PsyMemoryWallet::inject_eth_personal_signature`).
#[derive(Debug, Clone)]
pub struct ExternalEthPersonalSignUser {
    compressed_public_key: CompressedPublicKey,
    signature: Option<PsyCompressedSecp256K1Signature>,
}

impl ExternalEthPersonalSignUser {
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

    /// Identical `public_key_param` derivation to the held-key / raw-eth_sign
    /// paths (`hash_no_pad_compressed_public_key`). Only the circuit
    /// fingerprint differs, which is what makes this a distinct identity.
    fn public_key_param(&self) -> QHashOut<GoldilocksField> {
        hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(self.compressed_public_key)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureUser for ExternalEthPersonalSignUser {
    async fn public_key_info(
        &self,
        _wallet: &PsyMemoryWallet,
        circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
    ) -> Result<ZKPublicKeyInfo<GoldilocksField>> {
        let public_key_param = self.public_key_param();
        let fingerprint = circuit_manager.eth_personal_secp_circuit_fingerprint().await?;
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
        // Mode-A: the signature was produced externally (MetaMask `personal_sign`)
        // over EXACTLY the sighash this session computed. Re-prove it through
        // the EIP-191 circuit, which recomputes `keccak256(prefix || sighash)`
        // in-circuit. Fail fast with a clear error if no (or a stale) signature
        // was injected — the circuit would reject it anyway, but opaquely.
        let signature = self.signature.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "ExternalEthPersonalSignUser has no signature yet: register the user PK-first, generate the trace, then re-inject a MetaMask signature over the session sighash before proving"
            )
        })?;
        let signed_sighash = QHashOut::from(signature.message);
        anyhow::ensure!(
            signed_sighash == sighash,
            "injected MetaMask signature is over message {} but the session sighash is {} — the personal_sign must cover the exact session sighash",
            signed_sighash,
            sighash
        );
        circuit_manager.prove_eth_personal_secp_sign(*signature).await
    }

    async fn circuit_info(
        &self,
        _wallet: &PsyMemoryWallet,
        circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
        _context: &SignContext,
    ) -> Result<SignatureCircuitInfo> {
        Ok(SignatureCircuitInfo {
            circuit_fingerprint: circuit_manager.eth_personal_secp_circuit_fingerprint().await?,
            verifier_config: circuit_manager.eth_personal_secp_circuit_verifier_config().await?,
        })
    }
}
