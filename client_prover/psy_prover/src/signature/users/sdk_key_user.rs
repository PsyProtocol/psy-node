use anyhow::{anyhow, Result};
use async_trait::async_trait;
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::config::store_config::{PsyPlonky2Config, PsyProof};
use psy_crypto::signature::zk::data::ZKPublicKeyInfo;
use psy_ups_circuit::signature::sdk_key::get_sdk_key_public_key_param;
use psy_vm::ups::circuit_manager::UPSCircuitManager;

use crate::{
    signature::{
        context::SignContext,
        traits::{SignatureCircuitInfo, SignatureUser},
    },
    wallet::memory_wallet::PsyMemoryWallet,
};

#[derive(Debug, Clone)]
pub struct SDKKeyUser {
    private_key: QHashOut<GoldilocksField>,
    fingerprint: QHashOut<GoldilocksField>,
}

impl SDKKeyUser {
    pub fn new(private_key: QHashOut<GoldilocksField>, fingerprint: QHashOut<GoldilocksField>) -> Self {
        Self { private_key, fingerprint }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureUser for SDKKeyUser {
    async fn public_key_info(
        &self,
        _wallet: &PsyMemoryWallet,
        _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
    ) -> Result<ZKPublicKeyInfo<GoldilocksField>> {
        Ok(ZKPublicKeyInfo {
            fingerprint: self.fingerprint,
            public_key_param: get_sdk_key_public_key_param(&self.private_key),
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
            .sdk_key_signature_input
            .as_ref()
            .ok_or_else(|| anyhow!("SDK key witness input missing for SDK key user"))?;

        if context.psy_signature_input.is_some() || context.plonky2_signature_input.is_some() {
            return Err(anyhow!("SDKKeyUser cannot handle DPN or PLONKY2 SDC inputs"));
        }

        let circuit = wallet
            .get_sdk_key_circuit(&self.fingerprint)
            .ok_or_else(|| anyhow!("SDK key circuit `{}` not registered", self.fingerprint))?;

        circuit.prove(self.private_key, input, sighash).await
    }

    async fn circuit_info(
        &self,
        wallet: &PsyMemoryWallet,
        _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
        context: &SignContext,
    ) -> Result<SignatureCircuitInfo> {
        if context.sdk_key_signature_input.is_none() {
            return Err(anyhow!("SDK key witness input missing for SDK key user"));
        }

        let circuit = wallet
            .get_sdk_key_circuit(&self.fingerprint)
            .ok_or_else(|| anyhow!("SDK key circuit `{}` not registered", self.fingerprint))?;

        Ok(SignatureCircuitInfo {
            circuit_fingerprint: circuit.get_fingerprint(),
            verifier_config: circuit
                .get_verifier_config_ref()
                .ok_or_else(|| anyhow!("Verifier config not available"))?
                .clone(),
        })
    }
}
