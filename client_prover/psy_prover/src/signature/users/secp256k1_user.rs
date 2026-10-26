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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn held_key_produces_a_signature_bound_to_the_sighash() {
        let key = QHashOut::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a").unwrap();
        let sighash = QHashOut::from_str("f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d").unwrap();
        let signature = SECP256K1User::new(key).raw_signature(sighash).unwrap();

        assert_eq!(signature.message, Hash256::from(sighash));
        assert_ne!(signature.signature, [0; 64]);
        assert_ne!(signature.public_key, [0; 33]);
    }

    #[test]
    fn invalid_zero_private_key_is_rejected_when_signing() {
        let zero = QHashOut::from_str("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        assert!(SECP256K1User::new(zero).raw_signature(zero).is_err());
    }

    #[tokio::test]
    async fn secp_user_reports_manager_bound_public_key_and_circuit_info() {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let session = session.read();
        let wallet = &session.wallet;
        let manager = wallet.random_circuit_manager();

        let key = QHashOut::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a").unwrap();
        let user = SECP256K1User::new(key);

        let info = user.public_key_info(wallet, manager.as_ref()).await.unwrap();
        let expected_param =
            hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(get_secp_public_key(key).unwrap());
        assert_eq!(info.public_key_param, expected_param);

        let circuit_info = user
            .circuit_info(wallet, manager.as_ref(), &SignContext::new(QHashOut::ZERO))
            .await
            .unwrap();
        assert_eq!(circuit_info.circuit_fingerprint, info.fingerprint);

        // an unusable private key fails during raw-signature recovery, before
        // any circuit proving is attempted
        let error = SECP256K1User::new(QHashOut::ZERO)
            .sign(wallet, manager.as_ref(), &SignContext::new(QHashOut::ZERO), QHashOut::ZERO)
            .await
            .unwrap_err();
        assert!(!error.to_string().is_empty());
    }
}
