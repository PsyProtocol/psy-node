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
        let plonky2_input = context
            .plonky2_signature_input
            .as_ref()
            .ok_or_else(|| anyhow!("PLONKY2 signature input missing for PLONKY2 user"))?;

        if context.psy_signature_input.is_some() {
            return Err(anyhow!("SDKeyPlonky2User cannot handle PSY witness input"));
        }

        let mut circuit = wallet
            .get_plonky2_software_defined_circuit_mut(&self.fingerprint)
            .ok_or_else(|| anyhow!("PLONKY2 software defined circuit `{}` not registered", self.fingerprint))?;

        circuit.prove(self.private_key, plonky2_input, sighash).await
    }

    async fn circuit_info(
        &self,
        wallet: &PsyMemoryWallet,
        _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
        context: &SignContext,
    ) -> Result<SignatureCircuitInfo> {
        if context.plonky2_signature_input.is_none() {
            return Err(anyhow!("PLONKY2 signature input missing for PLONKY2 user"));
        }

        if context.psy_signature_input.is_some() {
            return Err(anyhow!("SDKeyPlonky2User cannot handle PSY witness input"));
        }

        let circuit = wallet
            .get_plonky2_software_defined_circuit(&self.fingerprint)
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
