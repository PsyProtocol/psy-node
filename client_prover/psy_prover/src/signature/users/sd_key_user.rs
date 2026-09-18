use anyhow::{anyhow, Result};
use async_trait::async_trait;
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::config::store_config::{PsyPlonky2Config, PsyProof};
use psy_crypto::signature::zk::data::ZKPublicKeyInfo;
use psy_ups_circuit::signature::sd_key::get_sd_key_public_key_param;
use psy_vm::ups::circuit_manager::UPSCircuitManager;

use crate::{
    signature::{
        context::SignContext,
        traits::{SignatureCircuitInfo, SignatureUser},
    },
    wallet::memory_wallet::PsyMemoryWallet,
};

#[derive(Debug, Clone)]
pub struct SDKeyUser {
    private_key: QHashOut<GoldilocksField>,
    fingerprint: QHashOut<GoldilocksField>,
}

impl SDKeyUser {
    pub fn new(private_key: QHashOut<GoldilocksField>, fingerprint: QHashOut<GoldilocksField>) -> Self {
        Self { private_key, fingerprint }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureUser for SDKeyUser {
    async fn public_key_info(
        &self,
        _wallet: &PsyMemoryWallet,
        _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
    ) -> Result<ZKPublicKeyInfo<GoldilocksField>> {
        Ok(ZKPublicKeyInfo {
            fingerprint: self.fingerprint,
            public_key_param: get_sd_key_public_key_param(&self.private_key),
        })
    }

    async fn sign(
        &self,
        wallet: &PsyMemoryWallet,
        _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
        context: &SignContext,
        sighash: QHashOut<GoldilocksField>,
    ) -> Result<PsyProof> {
        let input = context
            .sd_key_signature_input
            .as_ref()
            .ok_or_else(|| anyhow!("SD key witness input missing for SD key user"))?;

        if context.psy_signature_input.is_some() || context.plonky2_signature_input.is_some() {
            return Err(anyhow!("SDKeyUser cannot handle DPN or PLONKY2 SDC inputs"));
        }

        let circuit = wallet
            .get_sd_key_circuit(&self.fingerprint)
            .ok_or_else(|| anyhow!("SD key circuit `{}` not registered", self.fingerprint))?;

        circuit.prove(self.private_key, input, sighash).await
    }

    async fn circuit_info(
        &self,
        wallet: &PsyMemoryWallet,
        _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
        context: &SignContext,
    ) -> Result<SignatureCircuitInfo> {
        if context.sd_key_signature_input.is_none() {
            return Err(anyhow!("SD key witness input missing for SD key user"));
        }

        let circuit = wallet
            .get_sd_key_circuit(&self.fingerprint)
            .ok_or_else(|| anyhow!("SD key circuit `{}` not registered", self.fingerprint))?;

        Ok(SignatureCircuitInfo {
            circuit_fingerprint: circuit.get_fingerprint(),
            verifier_config: circuit
                .get_verifier_config_ref()
                .ok_or_else(|| anyhow!("Verifier config not available"))?
                .clone(),
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::str::FromStr;

    use plonky2::field::types::Field;
    use psy_vm::ups::sd_key::SDKeyCircuitWitnessInput;

    use super::*;

    #[test]
    fn constructor_preserves_key_and_fingerprint() {
        let key = QHashOut::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a").unwrap();
        let fingerprint = QHashOut::from_str("f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d").unwrap();
        let user = SDKeyUser::new(key, fingerprint);
        assert_eq!(user.private_key, key);
        assert_eq!(user.fingerprint, fingerprint);
    }

    fn sd_key_witness() -> SDKeyCircuitWitnessInput {
        SDKeyCircuitWitnessInput {
            circuit_inputs: Vec::new(),
            transaction_infos: Vec::new(),
            tx_stack_hash: QHashOut::ZERO,
            tx_count: GoldilocksField::ZERO,
            state_reader_results: None,
            secp256k1_slots: Vec::new(),
            checkpoint_id: GoldilocksField::ZERO,
            user_id: GoldilocksField::ZERO,
        }
    }

    #[tokio::test]
    async fn sd_key_user_reports_registered_circuit_info_and_proves_through_it() {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let fingerprint = session.write().register_sd_key_circuit(&[3], &[4], 2).await.unwrap();
        let session = session.read();
        let wallet = &session.wallet;
        let manager = wallet.random_circuit_manager();

        let key = QHashOut::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a").unwrap();
        let user = SDKeyUser::new(key, fingerprint);

        let info = user.public_key_info(wallet, manager.as_ref()).await.unwrap();
        assert_eq!(info.fingerprint, fingerprint);
        assert_eq!(info.public_key_param, get_sd_key_public_key_param(&key));

        let context = SignContext::new(fingerprint).with_sd_key_signature_input(sd_key_witness(), 1, 2, QHashOut::ZERO, QHashOut::ZERO);
        let circuit_info = user.circuit_info(wallet, manager.as_ref(), &context).await.unwrap();
        assert_eq!(circuit_info.circuit_fingerprint, fingerprint);

        // the empty witness mismatches the registered circuit's two
        // introspectable tx slots, so proving fails deterministically after
        // dispatching into the circuit
        let error = user.sign(wallet, manager.as_ref(), &context, QHashOut::ZERO).await.unwrap_err();
        assert!(!error.to_string().is_empty());
    }

    #[tokio::test]
    async fn sd_key_user_validates_witness_and_registration_before_proving() {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let session = session.read();
        let wallet = &session.wallet;
        let manager = wallet.random_circuit_manager();

        let key = QHashOut::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a").unwrap();
        let unregistered_fingerprint = QHashOut::from_str("f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d").unwrap();
        let user = SDKeyUser::new(key, unregistered_fingerprint);
        let sighash = QHashOut::ZERO;

        let missing = SignContext::new(unregistered_fingerprint);
        let error = user.sign(wallet, manager.as_ref(), &missing, sighash).await.unwrap_err();
        assert!(error.to_string().contains("SD key witness input missing"));

        let conflicting = SignContext::new(unregistered_fingerprint)
            .with_sd_key_signature_input(sd_key_witness(), 1, 2, QHashOut::ZERO, QHashOut::ZERO)
            .with_psy_signature_input(
                psy_provider::request::DPNSoftwareDefinedSignatureInput {
                    cfc_input: Default::default(),
                },
                1,
                2,
                QHashOut::ZERO,
                QHashOut::ZERO,
            );
        let error = user.sign(wallet, manager.as_ref(), &conflicting, sighash).await.unwrap_err();
        assert!(error.to_string().contains("cannot handle DPN or PLONKY2 SDC inputs"));

        let unregistered =
            SignContext::new(unregistered_fingerprint).with_sd_key_signature_input(sd_key_witness(), 1, 2, QHashOut::ZERO, QHashOut::ZERO);
        let error = user.sign(wallet, manager.as_ref(), &unregistered, sighash).await.unwrap_err();
        assert!(error.to_string().contains("not registered"));

        let error = user.circuit_info(wallet, manager.as_ref(), &missing).await.unwrap_err();
        assert!(error.to_string().contains("SD key witness input missing"));
        let error = user.circuit_info(wallet, manager.as_ref(), &unregistered).await.unwrap_err();
        assert!(error.to_string().contains("not registered"));
    }
}
