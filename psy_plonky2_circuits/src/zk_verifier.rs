use parth_core::{pgoldilocks::QHashOut, protocol::core_types::{Q256BitHash, QZKProofPublicInputsHasherReader, QZKProofVerifier}};
use plonky2::{hash::hash_types::HashOut, plonk::{config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig}, proof::ProofWithPublicInputs}};
use psy_core::job::job_id::ProvingJobCircuitType;
use psy_core::{constants::chain_id::PsyChainNetworkType, network_config::get_circuit_config_for_network};
use psy_data::protocol::canonical_chain::NetworkId;
use psy_node_core::queue::realm_user_update_verifier_profile::{
    RealmUserUpdateVerifierBackend, RealmUserUpdateVerifierProfile,
};
use psy_plonky2_basic_helpers::verifier::{
    circuit_library::CircuitInfoLibraryCore,
    generic_circuit_library::GenericCircuitVerifier,
};

use crate::{
    circuit_library::get_plonky2_circuit_library_and_prover_for_network,
    generated::{cached_circuit_library::get_cached_circuit_library, cached_common_data::get_cached_common_data_library},
};

#[derive(Clone, Debug)]
pub struct PsyPlonky2ZKVerifier<C: GenericConfig<D>, const D: usize> {
    pub gcv: GenericCircuitVerifier<C, D>,
}
impl<C: GenericConfig<D>, const D: usize> PsyPlonky2ZKVerifier<C, D> {
    pub fn new(gcv: GenericCircuitVerifier<C, D>,) -> Self {
        Self {
            gcv,
        }
    }
    pub fn from_cached() -> Self 
    where
        C::Hasher: AlgebraicHasher<C::F>,
    {
        let a = get_cached_circuit_library();
        let b = get_cached_common_data_library();
        let gcv = GenericCircuitVerifier::<C, D>{
            library: a,
            common: b
        };
        Self::new(gcv)
    }

}

impl PsyPlonky2ZKVerifier<PoseidonGoldilocksConfig, 2> {
    pub fn for_network(network: PsyChainNetworkType) -> anyhow::Result<Self> {
        let (gcv, _) = get_plonky2_circuit_library_and_prover_for_network::<PoseidonGoldilocksConfig, 2>(network)?;
        Ok(Self::new(gcv))
    }

    /// Derive the durable UserEndCap verifier profile from the exact loaded
    /// verifier library. This uses canonical hash bytes, never type names or
    /// debug formatting. The common-data commitment is the validated cached
    /// library commitment; its current CDV1 derivation remains an explicit
    /// protocol version in the profile.
    pub fn realm_user_update_verifier_profile(
        &self,
        network: PsyChainNetworkType,
    ) -> anyhow::Result<RealmUserUpdateVerifierProfile> {
        const PUBLIC_INPUT_LAYOUT_VERSION: u16 = 1;
        const BINCODE_PROOF_CODEC_VERSION: u16 = 1;

        let circuit = ProvingJobCircuitType::UserEndCap;
        let verifier_fingerprint = self
            .gcv
            .library
            .get_fingerprint(circuit)?
            .into_owned_32bytes();
        let common_index = *self
            .gcv
            .common
            .common_circuit_map
            .get(&circuit)
            .ok_or_else(|| anyhow::anyhow!("UserEndCap common-data mapping missing"))?;
        let common_data_fingerprint = self
            .gcv
            .common
            .common_data_hashes
            .get(common_index)
            .ok_or_else(|| anyhow::anyhow!("UserEndCap common-data commitment missing"))?
            .0;
        let config = get_circuit_config_for_network(network);
        RealmUserUpdateVerifierProfile::try_new(
            NetworkId::from_network_type(network),
            u8::try_from(config.global_user_tree_height)
                .map_err(|_| anyhow::anyhow!("global user tree height out of range"))?,
            RealmUserUpdateVerifierBackend::Plonky2PoseidonGoldilocksD2,
            PUBLIC_INPUT_LAYOUT_VERSION,
            BINCODE_PROOF_CODEC_VERSION,
            verifier_fingerprint,
            common_data_fingerprint,
        )
        .map_err(Into::into)
    }
}
impl<C: GenericConfig<D>, const D: usize> QZKProofPublicInputsHasherReader<QHashOut<C::F>, ProofWithPublicInputs<C::F, C, D>> for PsyPlonky2ZKVerifier<C, D> 
where
    C::Hasher: AlgebraicHasher<C::F> {
    fn get_proof_public_inputs_hash(proof: &ProofWithPublicInputs<C::F, C, D>) -> anyhow::Result<QHashOut<C::F>> {
        if proof.public_inputs.len() != 4 {
            return Err(anyhow::anyhow!("Invalid number of public inputs in proof, expected 4, got {}", proof.public_inputs.len()));
        }
        Ok(QHashOut(HashOut{
            elements: [
                proof.public_inputs[0],
                proof.public_inputs[1],
                proof.public_inputs[2],
                proof.public_inputs[3],
            ],
        }))
    }
    fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let proof: ProofWithPublicInputs<C::F, C, D> = bincode::deserialize(bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize proof: {}", e))?;
        Ok(proof)
    }
}
impl<C: GenericConfig<D>, const D: usize> QZKProofVerifier<QHashOut<C::F>, ProofWithPublicInputs<C::F, C, D>> for PsyPlonky2ZKVerifier<C, D> 
where
    C::Hasher: AlgebraicHasher<C::F>,{
    fn verify_zk_proof(&self, circuit_type: u32, proof: &ProofWithPublicInputs<C::F, C, D>) -> anyhow::Result<QHashOut<C::F>> {
        let proving_job_circuit_type = ProvingJobCircuitType::try_from_u32(circuit_type)?;
        self.gcv.verify_proof_of_type(proving_job_circuit_type, proof)?;
        Self::get_proof_public_inputs_hash(proof)
    }
}

#[cfg(test)]
mod verifier_profile_tests {
    use super::*;

    #[test]
    fn cached_user_end_cap_profile_is_exact_and_deterministic() {
        let verifier =
            PsyPlonky2ZKVerifier::<PoseidonGoldilocksConfig, 2>::from_cached();
        let first = verifier
            .realm_user_update_verifier_profile(PsyChainNetworkType::LocalDevnet)
            .unwrap();
        let second = verifier
            .realm_user_update_verifier_profile(PsyChainNetworkType::LocalDevnet)
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.backend(),
            RealmUserUpdateVerifierBackend::Plonky2PoseidonGoldilocksD2
        );
        assert_eq!(first.global_user_tree_height(), 32);
        assert_eq!(
            first.verifier_fingerprint(),
            &verifier
                .gcv
                .library
                .get_fingerprint(ProvingJobCircuitType::UserEndCap)
                .unwrap()
                .into_owned_32bytes()
        );
        assert_eq!(
            RealmUserUpdateVerifierProfile::from_canonical_bytes(
                &first.to_canonical_bytes()
            )
            .unwrap(),
            first
        );
    }
}
