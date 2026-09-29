//! `EthPersonalSignSECP256K1User` — the HELD-KEY counterpart to
//! [`super::external_eth_personal_user::ExternalEthPersonalSignUser`].
//!
//! Holds the secp256k1 private key in the wallet (like [`SECP256K1User`]) but
//! signs EIP-191 style: the ECDSA prehash is
//! `keccak256("\x19Ethereum Signed Message:\n32" || sighash)`, byte-identical
//! to a MetaMask `personal_sign` over the raw sighash. The resulting
//! `PsyCompressedSecp256K1Signature` is proved through the SAME EIP-191 circuit
//! (`prove_eth_personal_secp_sign`) as the externally injected variant, so both
//! report the identical circuit fingerprint / `public_key_param` and are
//! interchangeable identities — differing only in where the signature comes
//! from.

use anyhow::Result;
use async_trait::async_trait;
use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonPermutation};
use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut};
use psy_client_data::config::store_config::{PsyPlonky2Config, PsyProof};
use psy_crypto::signature::{
    secp256k1::{
        core::PsyCompressedSecp256K1Signature,
        wallet::{eth_personal_sign_digest, get_secp_public_key, hash_no_pad_compressed_public_key, secp256k1_sign_eth_personal},
    },
    zk::data::ZKPublicKeyInfo,
};
use psy_ups_circuit::signature::reward_authorization::{RewardAuthorizationCircuits, RewardAuthorizationContext, RewardAuthorizationInput};
use psy_vm::reward_authorization::RewardAuthorizationWitness;
use psy_vm::ups::circuit_manager::UPSCircuitManager;

use crate::{
    signature::{
        context::SignContext,
        traits::{SignatureCircuitInfo, SignatureUser},
    },
    wallet::memory_wallet::PsyMemoryWallet,
};

/// A signature user that holds a secp256k1 private key and signs EIP-191
/// (`personal_sign`) digests locally.
#[derive(Debug, Clone)]
pub struct EthPersonalSignSECP256K1User {
    private_key: QHashOut<GoldilocksField>,
}

impl EthPersonalSignSECP256K1User {
    pub fn new(private_key: QHashOut<GoldilocksField>) -> Self {
        Self { private_key }
    }

    fn raw_signature(&self, sighash: QHashOut<GoldilocksField>) -> Result<PsyCompressedSecp256K1Signature> {
        let hash256: Hash256 = self.private_key.into();
        let signing_key = SigningKey::from_slice(&hash256.0)?;
        secp256k1_sign_eth_personal(signing_key, sighash)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureUser for EthPersonalSignSECP256K1User {
    fn prove_reward_authorization(&self, context: &RewardAuthorizationContext, circuits: &RewardAuthorizationCircuits) -> Result<Option<PsyProof>> {
        let message = context.message()?;
        let private_key: Hash256 = self.private_key.into();
        let key = SigningKey::from_slice(&private_key.0)?;
        let signature: k256::ecdsa::Signature = key.sign_prehash(&eth_personal_sign_digest(&message))?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let input = RewardAuthorizationInput {
            context: context.clone(),
            authorization: RewardAuthorizationWitness::PersonalSign {
                compressed_public_key: key.verifying_key().to_encoded_point(true).as_bytes().try_into()?,
                signature_rs: signature.to_bytes().into(),
            },
        };
        circuits.personal_sign.prove(&input).map(Some)
    }

    async fn public_key_info(
        &self,
        _wallet: &PsyMemoryWallet,
        circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
    ) -> Result<ZKPublicKeyInfo<GoldilocksField>> {
        let public_key = get_secp_public_key(self.private_key)?;
        let public_key_param = hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(public_key);
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
        let ecc_signature = self.raw_signature(sighash)?;
        circuit_manager.prove_eth_personal_secp_sign(ecc_signature).await
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
