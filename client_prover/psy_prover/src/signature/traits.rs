use std::fmt;

use anyhow::Result;
use async_trait::async_trait;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::circuit_data::VerifierOnlyCircuitData};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::config::store_config::{PsyHasher, PsyPlonky2Config, PsyProof};
use psy_crypto::{hash::traits::qhashable::QFieldHashable, signature::zk::data::ZKPublicKeyInfo};
use psy_vm::ups::circuit_manager::UPSCircuitManager;

use super::context::SignContext;
use crate::wallet::memory_wallet::PsyMemoryWallet;

pub struct SignatureCircuitInfo {
    pub circuit_fingerprint: QHashOut<GoldilocksField>,
    pub verifier_config: VerifierOnlyCircuitData<PsyPlonky2Config, 2>,
}

impl fmt::Debug for SignatureCircuitInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureCircuitInfo")
            .field("circuit_fingerprint", &self.circuit_fingerprint)
            .field("verifier_config", &"...")
            .finish()
    }
}

pub struct SignatureResult {
    pub proof: PsyProof,
    pub circuit_info: SignatureCircuitInfo,
}

impl fmt::Debug for SignatureResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureResult")
            .field("proof_public_inputs", &self.proof.public_inputs)
            .field("circuit_info", &self.circuit_info)
            .finish()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait SignatureUser: fmt::Debug + Send + Sync {
    async fn public_key_info(
        &self,
        wallet: &PsyMemoryWallet,
        circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
    ) -> Result<ZKPublicKeyInfo<GoldilocksField>>;

    async fn sign(
        &self,
        wallet: &PsyMemoryWallet,
        circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
        context: &SignContext,
        sighash: QHashOut<GoldilocksField>,
    ) -> Result<PsyProof>;

    async fn circuit_info(
        &self,
        _wallet: &PsyMemoryWallet,
        circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
        _context: &SignContext,
    ) -> Result<SignatureCircuitInfo>;

    async fn public_key_hash(
        &self,
        wallet: &PsyMemoryWallet,
        circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync),
    ) -> Result<QHashOut<GoldilocksField>> {
        let info = self.public_key_info(wallet, circuit_manager).await?;
        Ok(info.qfhash::<PsyHasher>())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use plonky2::{
        field::types::Field,
        hash::merkle_tree::MerkleCap,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, VerifierOnlyCircuitData},
        },
    };

    use super::*;

    #[test]
    fn circuit_info_debug_includes_fingerprint_and_redacts_verifier_config() {
        let fingerprint = QHashOut::<GoldilocksField>::from_values(1, 2, 3, 4);
        let info = SignatureCircuitInfo {
            circuit_fingerprint: fingerprint,
            verifier_config: VerifierOnlyCircuitData {
                constants_sigmas_cap: MerkleCap(vec![QHashOut::<GoldilocksField>::from_values(5, 6, 7, 8).0]),
                circuit_digest: QHashOut::<GoldilocksField>::from_values(9, 10, 11, 12).0,
            },
        };

        let fingerprint_debug = format!("{fingerprint:?}");
        let verifier_digest_debug = format!("{:?}", info.verifier_config.circuit_digest);
        let verifier_cap_debug = format!("{:?}", info.verifier_config.constants_sigmas_cap);
        let debug = format!("{info:?}");
        assert!(debug.contains("SignatureCircuitInfo"));
        assert!(debug.contains(&fingerprint_debug));
        assert!(debug.contains("verifier_config: \"...\""));
        assert!(!debug.contains(&verifier_digest_debug));
        assert!(!debug.contains(&verifier_cap_debug));
    }

    #[test]
    fn signature_result_debug_exposes_public_inputs_without_expanding_the_proof() {
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(CircuitConfig::standard_recursion_config());
        let public_input = builder.add_virtual_target();
        builder.register_public_input(public_input);
        let data = builder.build::<PsyPlonky2Config>();

        let mut witness = PartialWitness::new();
        witness
            .set_target(public_input, GoldilocksField::from_canonical_u64(13))
            .expect("public input target should accept a field element");
        let proof = data.prove(witness).expect("minimal circuit should prove");
        let result = SignatureResult {
            proof,
            circuit_info: SignatureCircuitInfo {
                circuit_fingerprint: QHashOut::<GoldilocksField>::from_values(1, 2, 3, 4),
                verifier_config: data.verifier_only,
            },
        };

        let debug = format!("{result:?}");
        assert!(debug.contains("SignatureResult"));
        assert!(debug.contains("proof_public_inputs: [13]"));
        assert!(debug.contains("SignatureCircuitInfo"));
        assert!(!debug.contains("wires_cap"));
        assert!(!debug.contains("opening_proof"));
    }
}
