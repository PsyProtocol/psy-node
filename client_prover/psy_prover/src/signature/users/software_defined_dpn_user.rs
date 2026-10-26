use anyhow::{anyhow, Result};
use async_trait::async_trait;
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::config::store_config::{PsyPlonky2Config, PsyProof};
use psy_crypto::signature::zk::data::ZKPublicKeyInfo;
use psy_ups_circuit::signature::software_defined::get_sdc_public_key_param;
use psy_vm::ups::circuit_manager::UPSCircuitManager;

use crate::{
    signature::{
        context::SignContext,
        traits::{SignatureCircuitInfo, SignatureUser},
    },
    wallet::memory_wallet::PsyMemoryWallet,
};

/// Software-Defined DPN (Data Processing Network) signature user.
/// Handles signatures for Psy/DPN-based software-defined circuits.
#[derive(Debug, Clone)]
pub struct SoftwareDefinedDpnUser {
    private_key: QHashOut<GoldilocksField>,
    fingerprint: QHashOut<GoldilocksField>,
}

impl SoftwareDefinedDpnUser {
    pub fn new(private_key: QHashOut<GoldilocksField>, fingerprint: QHashOut<GoldilocksField>) -> Self {
        Self { private_key, fingerprint }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureUser for SoftwareDefinedDpnUser {
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
        let psy_signature_input = context
            .psy_signature_input
            .as_ref()
            .ok_or_else(|| anyhow!("PSY witness input missing for DPN user"))?;

        if context.plonky2_signature_input.is_some() {
            return Err(anyhow!("SoftwareDefinedDpnUser cannot handle PLONKY2 input"));
        }

        let mut circuit = wallet
            .get_psy_software_defined_circuit_mut(&self.fingerprint)
            .ok_or_else(|| anyhow!("PSY software defined circuit `{}` not registered", self.fingerprint))?;

        circuit.prove(self.private_key, psy_signature_input, sighash).await
    }

    async fn circuit_info(
        &self,
        wallet: &PsyMemoryWallet,
        _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
        context: &SignContext,
    ) -> Result<SignatureCircuitInfo> {
        if context.psy_signature_input.is_none() {
            return Err(anyhow!("PSY witness input missing for DPN user"));
        }

        if context.plonky2_signature_input.is_some() {
            return Err(anyhow!("SoftwareDefinedDpnUser cannot handle PLONKY2 input"));
        }

        let circuit = wallet
            .get_psy_software_defined_circuit(&self.fingerprint)
            .ok_or_else(|| anyhow!("PSY software defined circuit `{}` not registered", self.fingerprint))?;

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

    use psy_crypto::hash::traits::qhashable::QFieldHashable;

    use super::*;

    #[test]
    fn constructor_preserves_key_and_fingerprint() {
        let key = QHashOut::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a").unwrap();
        let fingerprint = QHashOut::from_str("f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d").unwrap();
        let user = SoftwareDefinedDpnUser::new(key, fingerprint);
        assert_eq!(user.private_key, key);
        assert_eq!(user.fingerprint, fingerprint);
    }

    fn psy_input() -> psy_provider::request::DPNSoftwareDefinedSignatureInput {
        psy_provider::request::DPNSoftwareDefinedSignatureInput {
            cfc_input: Default::default(),
        }
    }

    fn plonky2_input() -> psy_vm::ups::signature::Plonky2SoftwareDefinedSignatureInput {
        psy_vm::ups::signature::Plonky2SoftwareDefinedSignatureInput {
            state_reader_results: psy_vm::ups::state_reader::StateReaderResults {
                state: Default::default(),
                state_cmds: Vec::new(),
                merkel_proofs: Vec::new(),
            },
            circuit_inputs: Vec::new(),
        }
    }

    #[tokio::test]
    async fn dpn_user_reports_public_key_param_without_circuit_registration() {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let session = session.read();
        let wallet = &session.wallet;
        let manager = wallet.random_circuit_manager();

        let key = QHashOut::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a").unwrap();
        let fingerprint = QHashOut::from_str("f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d").unwrap();
        let user = SoftwareDefinedDpnUser::new(key, fingerprint);

        let info = user.public_key_info(wallet, manager.as_ref()).await.unwrap();
        assert_eq!(info.fingerprint, fingerprint);
        assert_eq!(info.public_key_param, get_sdc_public_key_param(&key));

        let pk_hash = user.public_key_hash(wallet, manager.as_ref()).await.unwrap();
        assert_eq!(pk_hash, info.qfhash::<psy_client_data::config::store_config::PsyHasher>());
    }

    #[tokio::test]
    async fn dpn_user_sign_and_circuit_info_validate_inputs_before_proving() {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let session = session.read();
        let wallet = &session.wallet;
        let manager = wallet.random_circuit_manager();

        let key = QHashOut::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a").unwrap();
        let fingerprint = QHashOut::from_str("f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d").unwrap();
        let user = SoftwareDefinedDpnUser::new(key, fingerprint);
        let sighash = QHashOut::ZERO;

        let missing = SignContext::new(fingerprint);
        let error = user.sign(wallet, manager.as_ref(), &missing, sighash).await.unwrap_err();
        assert!(error.to_string().contains("PSY witness input missing"));

        let conflicting = SignContext::new(fingerprint)
            .with_psy_signature_input(psy_input(), 1, 2, QHashOut::ZERO, QHashOut::ZERO)
            .with_plonky2_signature_input(plonky2_input(), 1, 2, QHashOut::ZERO, QHashOut::ZERO);
        let error = user.sign(wallet, manager.as_ref(), &conflicting, sighash).await.unwrap_err();
        assert!(error.to_string().contains("cannot handle PLONKY2 input"));

        let unregistered = SignContext::new(fingerprint).with_psy_signature_input(psy_input(), 1, 2, QHashOut::ZERO, QHashOut::ZERO);
        let error = user.sign(wallet, manager.as_ref(), &unregistered, sighash).await.unwrap_err();
        assert!(error.to_string().contains("not registered"));

        let error = user.circuit_info(wallet, manager.as_ref(), &missing).await.unwrap_err();
        assert!(error.to_string().contains("PSY witness input missing"));
        let error = user.circuit_info(wallet, manager.as_ref(), &conflicting).await.unwrap_err();
        assert!(error.to_string().contains("cannot handle PLONKY2 input"));
        let error = user.circuit_info(wallet, manager.as_ref(), &unregistered).await.unwrap_err();
        assert!(error.to_string().contains("not registered"));
    }
}
