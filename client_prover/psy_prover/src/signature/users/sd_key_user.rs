use anyhow::{anyhow, Result};
use async_trait::async_trait;
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::config::store_config::{PsyPlonky2Config, PsyProof};
use psy_crypto::signature::zk::data::ZKPublicKeyInfo;
use psy_ups_circuit::signature::{
    sd_key_dpn::get_sd_key_public_key_param,
    sd_key_plonky2::get_sdc_public_key_param,
};
use psy_vm::ups::circuit_manager::UPSCircuitManager;

use crate::{
    signature::{
        context::{SdKeySignInput, SignContext},
        traits::{SignatureCircuitInfo, SignatureUser},
    },
    wallet::memory_wallet::PsyMemoryWallet,
};

/// A programmable, read-only DPN used as an SD-key authorization circuit.
///
/// This is the only SD-key mode besides [`SDKeyPlonky2User`]; the
/// wallet dispatches on the mode recorded at circuit registration.
#[derive(Debug, Clone)]
pub struct SDKeyDpnUser {
    private_key: QHashOut<GoldilocksField>,
    fingerprint: QHashOut<GoldilocksField>,
}

impl SDKeyDpnUser {
    pub fn new(private_key: QHashOut<GoldilocksField>, fingerprint: QHashOut<GoldilocksField>) -> Self {
        Self { private_key, fingerprint }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureUser for SDKeyDpnUser {
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
        let input = match context.sd_key_signature_input.as_ref() {
            Some(SdKeySignInput::Dpn(input)) => input,
            _ => return Err(anyhow!("SD-key DPN witness input missing for SDKeyDpnUser")),
        };

        let circuit = wallet
            .get_sd_key_circuit(&self.fingerprint)
            .ok_or_else(|| anyhow!("SD-key DPN circuit `{}` not registered", self.fingerprint))?;

        circuit.prove(self.private_key, input, sighash).await
    }

    async fn circuit_info(
        &self,
        wallet: &PsyMemoryWallet,
        _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
        context: &SignContext,
    ) -> Result<SignatureCircuitInfo> {
        if !matches!(context.sd_key_signature_input.as_ref(), Some(SdKeySignInput::Dpn(_))) {
            return Err(anyhow!("SD-key DPN witness input missing for SDKeyDpnUser"));
        }

        let circuit = wallet
            .get_sd_key_circuit(&self.fingerprint)
            .ok_or_else(|| anyhow!("SD-key DPN circuit `{}` not registered", self.fingerprint))?;

        Ok(SignatureCircuitInfo {
            circuit_fingerprint: circuit.get_fingerprint(),
            verifier_config: circuit
                .get_verifier_config_ref()
                .ok_or_else(|| anyhow!("Verifier config not available"))?
                .clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SDKeyPlonky2User {
    private_key: QHashOut<GoldilocksField>,
    fingerprint: QHashOut<GoldilocksField>,
}

impl SDKeyPlonky2User {
    pub fn new(private_key: QHashOut<GoldilocksField>, fingerprint: QHashOut<GoldilocksField>) -> Self {
        Self { private_key, fingerprint }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureUser for SDKeyPlonky2User {
    async fn public_key_info(
        &self,
        _wallet: &PsyMemoryWallet,
        _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
    ) -> Result<ZKPublicKeyInfo<GoldilocksField>> {
        let public_key_param = get_sdc_public_key_param(&self.private_key);
        Ok(ZKPublicKeyInfo {
            fingerprint: self.fingerprint,
            public_key_param,
        })
    }

    async fn sign(
        &self,
        wallet: &PsyMemoryWallet,
        _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
        context: &SignContext,
        sighash: QHashOut<GoldilocksField>,
    ) -> Result<PsyProof> {
        let plonky2_input = match context.sd_key_signature_input.as_ref() {
            Some(SdKeySignInput::Plonky2(input)) => input,
            _ => return Err(anyhow!("PLONKY2 signature input missing for PLONKY2 user")),
        };

        let mut circuit = wallet
            .get_sd_key_plonky2_circuit_mut(&self.fingerprint)
            .ok_or_else(|| anyhow!("PLONKY2 software defined circuit `{}` not registered", self.fingerprint))?;

        circuit.prove(self.private_key, plonky2_input, sighash).await
    }

    async fn circuit_info(
        &self,
        wallet: &PsyMemoryWallet,
        _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
        context: &SignContext,
    ) -> Result<SignatureCircuitInfo> {
        if !matches!(context.sd_key_signature_input.as_ref(), Some(SdKeySignInput::Plonky2(_))) {
            return Err(anyhow!("PLONKY2 signature input missing for PLONKY2 user"));
        }

        let circuit = wallet
            .get_sd_key_plonky2_circuit(&self.fingerprint)
            .ok_or_else(|| anyhow!("PLONKY2 software defined circuit `{}` not registered", self.fingerprint))?;

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

    use super::*;

    #[test]
    fn constructor_preserves_key_and_fingerprint() {
        let key = QHashOut::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a").unwrap();
        let fingerprint = QHashOut::from_str("f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d").unwrap();
        let user = SDKeyPlonky2User::new(key, fingerprint);
        assert_eq!(user.private_key, key);
        assert_eq!(user.fingerprint, fingerprint);
    }

    fn plonky2_input() -> psy_vm::ups::signature::SDKeyPlonky2CircuitWitnessInput {
        psy_vm::ups::signature::SDKeyPlonky2CircuitWitnessInput {
            state_reader_results: psy_vm::ups::state_reader::StateReaderResults {
                state: Default::default(),
                state_cmds: Vec::new(),
                merkel_proofs: Vec::new(),
            },
            circuit_inputs: Vec::new(),
        }
    }

    #[tokio::test]
    async fn plonky2_user_reports_public_key_param_without_circuit_registration() {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let session = session.read();
        let wallet = &session.wallet;
        let manager = wallet.random_circuit_manager();

        let key = QHashOut::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a").unwrap();
        let fingerprint = QHashOut::from_str("f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d").unwrap();
        let user = SDKeyPlonky2User::new(key, fingerprint);

        let info = user.public_key_info(wallet, manager.as_ref()).await.unwrap();
        assert_eq!(info.fingerprint, fingerprint);
        assert_eq!(info.public_key_param, get_sdc_public_key_param(&key));
    }

    #[tokio::test]
    async fn plonky2_user_sign_and_circuit_info_validate_inputs_before_proving() {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let session = session.read();
        let wallet = &session.wallet;
        let manager = wallet.random_circuit_manager();

        let key = QHashOut::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a").unwrap();
        let fingerprint = QHashOut::from_str("f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d").unwrap();
        let user = SDKeyPlonky2User::new(key, fingerprint);
        let sighash = QHashOut::ZERO;

        let missing = SignContext::new(fingerprint);
        let error = user.sign(wallet, manager.as_ref(), &missing, sighash).await.unwrap_err();
        assert!(error.to_string().contains("PLONKY2 signature input missing"));

        let unregistered = SignContext::new(fingerprint).with_sd_key_input(
            SdKeySignInput::Plonky2(plonky2_input()),
            1,
            2,
            QHashOut::ZERO,
            QHashOut::ZERO,
        );
        let error = user.sign(wallet, manager.as_ref(), &unregistered, sighash).await.unwrap_err();
        assert!(error.to_string().contains("not registered"));

        let error = user.circuit_info(wallet, manager.as_ref(), &missing).await.unwrap_err();
        assert!(error.to_string().contains("PLONKY2 signature input missing"));
        let error = user.circuit_info(wallet, manager.as_ref(), &unregistered).await.unwrap_err();
        assert!(error.to_string().contains("not registered"));
    }
}
