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

use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonPermutation};
use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut, secp256k1::CompressedPublicKey};
use psy_client_data::config::store_config::{PsyPlonky2Config, PsyProof};
use psy_crypto::signature::{
    secp256k1::{
        core::PsyCompressedSecp256K1Signature,
        wallet::{eth_personal_sign_digest, hash_no_pad_compressed_public_key},
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

use super::external_secp256k1_user::{validate_compressed_public_key, validate_signature_prehash};

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
    pub fn new(compressed_public_key: CompressedPublicKey) -> Result<Self> {
        Ok(Self {
            compressed_public_key: validate_compressed_public_key(compressed_public_key)?,
            signature: None,
        })
    }

    /// Full form: carries an externally produced signature (used for proving).
    pub fn with_signature(signature: PsyCompressedSecp256K1Signature) -> Result<Self> {
        let digest = eth_personal_sign_digest(&signature.message.0);
        validate_signature_prehash(&signature, &digest, "external EIP-191")?;
        Ok(Self {
            compressed_public_key: validate_compressed_public_key(CompressedPublicKey(signature.public_key))?,
            signature: Some(signature),
        })
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
        let signature = self.signature.as_ref().context(
            "external EIP-191 signature missing: generate the trace, personal_sign its exact sig_hash bytes, then inject the signature before proving",
        )?;
        let expected_message = Hash256::from(sighash);
        ensure!(
            signature.message == expected_message,
            "external EIP-191 signature message does not match session sighash: signed={}, expected={}",
            hex::encode(signature.message.0),
            hex::encode(expected_message.0)
        );
        let digest = eth_personal_sign_digest(&expected_message.0);
        validate_signature_prehash(signature, &digest, "external EIP-191")?;
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use k256::ecdsa::SigningKey;
    use psy_crypto::signature::secp256k1::wallet::secp256k1_sign_eth_personal;

    use super::*;

    fn valid_signature() -> PsyCompressedSecp256K1Signature {
        let key = SigningKey::from_slice(&[2_u8; 32]).unwrap();
        secp256k1_sign_eth_personal(key, QHashOut::<GoldilocksField>::from_values(5, 6, 7, 8)).unwrap()
    }

    #[test]
    fn rejects_malformed_personal_signature() {
        let malformed = PsyCompressedSecp256K1Signature {
            public_key: [0; 33],
            signature: [0; 64],
            message: Hash256([9; 32]),
        };
        assert!(ExternalEthPersonalSignUser::with_signature(malformed).is_err());
    }

    #[test]
    fn accepts_valid_public_key_and_personal_signature_with_same_identity() {
        let signature = valid_signature();
        let key_only = ExternalEthPersonalSignUser::new(CompressedPublicKey(signature.public_key)).unwrap();
        let signed = ExternalEthPersonalSignUser::with_signature(signature).unwrap();

        assert!(key_only.signature.is_none());
        assert!(signed.signature.is_some());
        assert_eq!(key_only.public_key_param(), signed.public_key_param());
    }

    #[test]
    fn rejects_invalid_public_key_and_tampered_personal_signature() {
        assert!(ExternalEthPersonalSignUser::new(CompressedPublicKey([0_u8; 33])).is_err());
        let mut signature = valid_signature();
        signature.signature[0] ^= 1;
        assert!(ExternalEthPersonalSignUser::with_signature(signature).is_err());
    }

    #[tokio::test]
    async fn external_eth_personal_user_reports_public_key_and_circuit_info() {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let session = session.read();
        let wallet = &session.wallet;
        let manager = wallet.random_circuit_manager();

        let user = ExternalEthPersonalSignUser::with_signature(valid_signature()).unwrap();
        let info = user.public_key_info(wallet, manager.as_ref()).await.unwrap();
        assert_eq!(info.public_key_param, user.public_key_param());

        let circuit_info = user
            .circuit_info(wallet, manager.as_ref(), &SignContext::new(QHashOut::ZERO))
            .await
            .unwrap();
        assert_eq!(circuit_info.circuit_fingerprint, info.fingerprint);
    }

    #[tokio::test]
    async fn external_eth_personal_sign_rejects_missing_and_mismatched_signatures() {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let session = session.read();
        let wallet = &session.wallet;
        let manager = wallet.random_circuit_manager();
        let context = SignContext::new(QHashOut::ZERO);

        let signature = valid_signature();
        let key_only = ExternalEthPersonalSignUser::new(CompressedPublicKey(signature.public_key)).unwrap();
        let error = key_only
            .sign(wallet, manager.as_ref(), &context, QHashOut::from_values(5, 6, 7, 8))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("signature missing"));

        let signed = ExternalEthPersonalSignUser::with_signature(signature).unwrap();
        let error = signed
            .sign(wallet, manager.as_ref(), &context, QHashOut::from_values(1, 1, 1, 1))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("does not match session sighash"));
    }
}
