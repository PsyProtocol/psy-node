use anyhow::Result;
use async_trait::async_trait;
use k256::ecdsa::SigningKey;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonPermutation};
use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut};
use psy_client_data::config::store_config::{PsyPlonky2Config, PsyProof};
use psy_crypto::signature::{
    secp256k1::{
        core::PsyCompressedSecp256K1Signature,
        wallet::{get_secp_public_key, hash_no_pad_compressed_public_key, secp256k1_sign},
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

#[derive(Debug, Clone)]
pub struct SECP256K1User {
    private_key: QHashOut<GoldilocksField>,
}

impl SECP256K1User {
    pub fn new(private_key: QHashOut<GoldilocksField>) -> Self {
        Self { private_key }
    }

    fn raw_signature(&self, sighash: QHashOut<GoldilocksField>) -> Result<PsyCompressedSecp256K1Signature> {
        let hash256: Hash256 = self.private_key.into();
        let signing_key = SigningKey::from_slice(&hash256.0)?;
        secp256k1_sign(signing_key, sighash)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureUser for SECP256K1User {
    async fn public_key_info(
        &self,
        _wallet: &PsyMemoryWallet,
        circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
    ) -> Result<ZKPublicKeyInfo<GoldilocksField>> {
        let public_key = get_secp_public_key(self.private_key)?;
        let public_key_param = hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(public_key);
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
        let ecc_signature = self.raw_signature(sighash)?;
        circuit_manager.prove_secp_sign(ecc_signature).await
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
