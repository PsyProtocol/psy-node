use anyhow::Result;
use async_trait::async_trait;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::config::store_config::{PsyPlonky2Config, PsyProof};
use psy_crypto::signature::zk::{data::ZKPublicKeyInfo, wallet::SimplePsyPrivateKey};
use psy_vm::ups::circuit_manager::UPSCircuitManager;

use crate::{
    signature::{
        context::SignContext,
        traits::{SignatureCircuitInfo, SignatureUser},
    },
    wallet::memory_wallet::PsyMemoryWallet,
};

#[derive(Debug, Clone)]
pub struct ZKUser {
    private_key: SimplePsyPrivateKey<GoldilocksField>,
}

impl ZKUser {
    pub fn new(private_key: SimplePsyPrivateKey<GoldilocksField>) -> Self {
        Self { private_key }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureUser for ZKUser {
    async fn public_key_info(
        &self,
        wallet: &PsyMemoryWallet,
        _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
    ) -> Result<ZKPublicKeyInfo<GoldilocksField>> {
        let fingerprint = wallet.zk_circuit_fingerprint().await?;
        let public_key_param = self.private_key.get_public_key_param::<PoseidonHash>();
        Ok(ZKPublicKeyInfo {
            fingerprint,
            public_key_param,
        })
    }

    async fn sign(
        &self,
        wallet: &PsyMemoryWallet,
        _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
        _context: &SignContext,
        sighash: QHashOut<GoldilocksField>,
    ) -> Result<PsyProof> {
        wallet.prove_zk_sign(self.private_key.private_key, sighash).await
    }

    async fn circuit_info(
        &self,
        wallet: &PsyMemoryWallet,
        _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
        _context: &SignContext,
    ) -> Result<SignatureCircuitInfo> {
        Ok(SignatureCircuitInfo {
            circuit_fingerprint: wallet.zk_circuit_fingerprint().await?,
            verifier_config: wallet.zk_circuit_verifier_config().await?,
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn constructor_retains_the_private_key() {
        let private_key = QHashOut::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a").unwrap();
        let user = ZKUser::new(private_key.into());

        assert_eq!(user.private_key.private_key, private_key);
    }

    #[tokio::test]
    async fn zk_user_derives_identity_and_circuit_info_from_the_wallet() {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let session = session.read();
        let wallet = &session.wallet;
        let manager = wallet.random_circuit_manager();

        let private_key = QHashOut::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a").unwrap();
        let user = ZKUser::new(private_key.into());

        let info = user.public_key_info(wallet, manager.as_ref()).await.unwrap();
        assert_eq!(info.fingerprint, wallet.zk_circuit_fingerprint().await.unwrap());
        assert_eq!(
            info.public_key_param,
            SimplePsyPrivateKey::new(private_key).get_public_key_param::<PoseidonHash>()
        );

        let circuit_info = user
            .circuit_info(wallet, manager.as_ref(), &SignContext::new(QHashOut::ZERO))
            .await
            .unwrap();
        assert_eq!(circuit_info.circuit_fingerprint, info.fingerprint);

        // held-key zk signing proves through the wallet's local zk-sign circuit
        let proof = user
            .sign(wallet, manager.as_ref(), &SignContext::new(info.fingerprint), QHashOut::ZERO)
            .await
            .unwrap();
        assert!(!proof.proof.wires_cap.0.is_empty());
    }
}
