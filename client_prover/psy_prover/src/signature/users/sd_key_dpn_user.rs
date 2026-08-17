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

/// A programmable, read-only DPN used as an SD-key authorization circuit.
///
/// Fixed-policy SD keys are handled by [`super::SDKeyUser`].
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
        let input = context
            .sd_key_signature_input
            .as_ref()
            .ok_or_else(|| anyhow!("SD-key DPN witness input missing for SDKeyDpnUser"))?;

        if context.psy_signature_input.is_some() || context.plonky2_signature_input.is_some() {
            return Err(anyhow!("SDKeyDpnUser cannot handle standard DPN or PLONKY2 SDC inputs"));
        }
        if wallet.get_sd_key_policy(&self.fingerprint).is_some() {
            return Err(anyhow!("SDKeyDpnUser cannot use fixed-policy SD-key circuit `{}`", self.fingerprint));
        }

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
        if context.sd_key_signature_input.is_none() {
            return Err(anyhow!("SD-key DPN witness input missing for SDKeyDpnUser"));
        }
        if wallet.get_sd_key_policy(&self.fingerprint).is_some() {
            return Err(anyhow!("SDKeyDpnUser cannot use fixed-policy SD-key circuit `{}`", self.fingerprint));
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
