use parth_core::protocol::core_types::{
    Q256BitHash, QZKProofPublicInputsHasherReader, QZKProofVerifier,
};
use psy_core::{
    constants::chain_id::PsyChainNetworkType, job::job_id::ProvingJobCircuitType,
    network_config::get_circuit_config_for_network,
};
use psy_data::protocol::canonical_chain::NetworkId;
use psy_node_core::queue::realm_user_update_verifier_profile::{
    RealmUserUpdateVerifierBackend, RealmUserUpdateVerifierProfile,
};

use crate::{
    proof::PsyTestJTMBProof,
    protocol_types::JTMBPoseidonGoldilocksConfig,
    utils::{
        circuit_info_library::{
            PsyJTMBCircuitInfoLibrary, PsyJTMBCircuitInfoLibraryCore,
        },
        generic_circuit_library::JTMBGenericCircuitVerifier,
        jtmb_standard_circuit::JTMBCircuitConfig,
        proof_serialization::deserialize_jtmb_proof,
    },
};


#[derive(Clone, Debug)]
pub struct PsyJTMBZKVerifier<C: JTMBCircuitConfig> {
    pub gcv: JTMBGenericCircuitVerifier<C>,
}
impl<C: JTMBCircuitConfig> PsyJTMBZKVerifier<C> {
    pub fn new(gcv: JTMBGenericCircuitVerifier<C>) -> Self {
        Self { gcv }
    }
}

impl PsyJTMBZKVerifier<JTMBPoseidonGoldilocksConfig> {
    /// Derive the durable UserEndCap verifier identity from the exact loaded
    /// JTMB library. The library fingerprint is cross-checked against the
    /// verifier data before either value is admitted into the profile.
    pub fn realm_user_update_verifier_profile(
        &self,
        network: PsyChainNetworkType,
    ) -> anyhow::Result<RealmUserUpdateVerifierProfile> {
        const PUBLIC_INPUT_LAYOUT_VERSION: u16 = 1;
        const PSY_SER_FIXED_96_PROOF_CODEC_VERSION: u16 = 1;
        const CONFIG_COMMITMENT_DOMAIN: &[u8] =
            b"psy/rollback/jtmb-user-end-cap-config/v1";

        let circuit = ProvingJobCircuitType::UserEndCap;
        let verifier_data = self.gcv.library.get_verifier_data(circuit)?;
        if verifier_data.circuit_type != circuit as u32 {
            anyhow::bail!(
                "JTMB UserEndCap verifier-data circuit mismatch: expected {}, got {}",
                circuit as u32,
                verifier_data.circuit_type
            );
        }
        if !matches!(verifier_data.signer_public_key_sign, 2 | 3) {
            anyhow::bail!(
                "JTMB UserEndCap verifier-data has invalid compressed-key prefix {}",
                verifier_data.signer_public_key_sign
            );
        }

        let library_fingerprint = self.gcv.library.get_fingerprint(circuit)?;
        let recomputed_fingerprint = verifier_data.get_fingerprint::<
            parth_core::PHash,
            parth_core::pgoldilocks::PoseidonHasher,
            parth_core::PF,
        >();
        if library_fingerprint != recomputed_fingerprint {
            anyhow::bail!(
                "JTMB UserEndCap library fingerprint does not match verifier data"
            );
        }

        // JTMB's testing verifier currently uses an all-zero raw circuit
        // configuration fingerprint. The durable profile forbids an empty
        // commitment, so commit the exact raw value with an explicit domain
        // and circuit discriminator rather than substituting an unrelated
        // digest or treating zero as missing.
        let mut config_commitment_input = Vec::with_capacity(
            CONFIG_COMMITMENT_DOMAIN.len() + 4 + verifier_data.circuit_config_fingerprint.len(),
        );
        config_commitment_input.extend_from_slice(CONFIG_COMMITMENT_DOMAIN);
        config_commitment_input.extend_from_slice(&verifier_data.circuit_type.to_be_bytes());
        config_commitment_input.extend_from_slice(&verifier_data.circuit_config_fingerprint);
        let common_data_fingerprint =
            parth_crypto::hash::sha256::CoreSha256Hasher::hash_bytes(
                &config_commitment_input,
            )
            .0;

        let config = get_circuit_config_for_network(network);
        RealmUserUpdateVerifierProfile::try_new(
            NetworkId::from_network_type(network),
            u8::try_from(config.global_user_tree_height)
                .map_err(|_| anyhow::anyhow!("global user tree height out of range"))?,
            RealmUserUpdateVerifierBackend::JtmbPoseidonGoldilocks,
            PUBLIC_INPUT_LAYOUT_VERSION,
            PSY_SER_FIXED_96_PROOF_CODEC_VERSION,
            library_fingerprint.into_owned_32bytes(),
            common_data_fingerprint,
        )
        .map_err(Into::into)
    }
}
impl<C: JTMBCircuitConfig> QZKProofPublicInputsHasherReader<C::Hash, PsyTestJTMBProof<C::Hash>> for PsyJTMBZKVerifier<C> 
{
    fn get_proof_public_inputs_hash(proof: &PsyTestJTMBProof<C::Hash>) -> anyhow::Result<C::Hash> {
        Ok(proof.public_inputs_hash)
    }
    fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        deserialize_jtmb_proof(bytes)
    }
}
impl<C: JTMBCircuitConfig> QZKProofVerifier<C::Hash, PsyTestJTMBProof<C::Hash>> for PsyJTMBZKVerifier<C> {
    fn verify_zk_proof(&self, circuit_type: u32, proof: &PsyTestJTMBProof<C::Hash>) -> anyhow::Result<C::Hash> {
        let proving_job_circuit_type = ProvingJobCircuitType::try_from_u32(circuit_type)?;
        self.gcv.verify_proof_of_type(proving_job_circuit_type, proof)?;
        Self::get_proof_public_inputs_hash(proof)
    }
}

#[cfg(test)]
mod verifier_profile_tests {
    use super::*;
    use crate::circuit_library::core::get_jtmb_circuit_library_and_prover_for_network;

    fn loaded_verifier() -> PsyJTMBZKVerifier<JTMBPoseidonGoldilocksConfig> {
        let (gcv, _) = get_jtmb_circuit_library_and_prover_for_network::<
            JTMBPoseidonGoldilocksConfig,
        >(PsyChainNetworkType::LocalDevnet)
        .unwrap();
        PsyJTMBZKVerifier::new(gcv)
    }

    #[test]
    fn loaded_user_end_cap_profile_is_exact_and_deterministic() {
        let verifier = loaded_verifier();
        let first = verifier
            .realm_user_update_verifier_profile(PsyChainNetworkType::LocalDevnet)
            .unwrap();
        let second = verifier
            .realm_user_update_verifier_profile(PsyChainNetworkType::LocalDevnet)
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(
            first.backend(),
            RealmUserUpdateVerifierBackend::JtmbPoseidonGoldilocks
        );
        assert_eq!(first.global_user_tree_height(), 32);
        assert_eq!(first.public_input_layout_version(), 1);
        assert_eq!(first.proof_codec_version(), 1);
        assert_eq!(
            first.verifier_fingerprint(),
            &verifier
                .gcv
                .library
                .get_fingerprint(ProvingJobCircuitType::UserEndCap)
                .unwrap()
                .into_owned_32bytes()
        );
        assert_ne!(first.common_data_fingerprint(), &[0; 32]);
        assert_eq!(
            RealmUserUpdateVerifierProfile::from_canonical_bytes(
                &first.to_canonical_bytes()
            )
            .unwrap(),
            first
        );
    }

    #[test]
    fn profile_rejects_library_and_verifier_data_fingerprint_drift() {
        let mut verifier = loaded_verifier();
        verifier
            .gcv
            .library
            .info_map
            .get_mut(&ProvingJobCircuitType::UserEndCap)
            .unwrap()
            .fingerprint = parth_core::PHash::from_owned_32bytes([7; 32]);

        let error = verifier
            .realm_user_update_verifier_profile(PsyChainNetworkType::LocalDevnet)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("library fingerprint does not match verifier data"));
    }

    #[test]
    fn profile_rejects_wrong_circuit_and_invalid_compressed_key_prefix() {
        let mut wrong_circuit = loaded_verifier();
        wrong_circuit
            .gcv
            .library
            .info_map
            .get_mut(&ProvingJobCircuitType::UserEndCap)
            .unwrap()
            .verifier_data
            .circuit_type = ProvingJobCircuitType::UserEndCap as u32 + 1;
        assert!(wrong_circuit
            .realm_user_update_verifier_profile(PsyChainNetworkType::LocalDevnet)
            .unwrap_err()
            .to_string()
            .contains("circuit mismatch"));

        let mut invalid_prefix = loaded_verifier();
        invalid_prefix
            .gcv
            .library
            .info_map
            .get_mut(&ProvingJobCircuitType::UserEndCap)
            .unwrap()
            .verifier_data
            .signer_public_key_sign = 4;
        assert!(invalid_prefix
            .realm_user_update_verifier_profile(PsyChainNetworkType::LocalDevnet)
            .unwrap_err()
            .to_string()
            .contains("invalid compressed-key prefix"));
    }

    #[test]
    fn profile_rejects_missing_user_end_cap() {
        let mut verifier = loaded_verifier();
        verifier
            .gcv
            .library
            .info_map
            .remove(&ProvingJobCircuitType::UserEndCap);
        assert!(verifier
            .realm_user_update_verifier_profile(PsyChainNetworkType::LocalDevnet)
            .is_err());
    }
}
