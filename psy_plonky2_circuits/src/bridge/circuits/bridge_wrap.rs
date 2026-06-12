pub use std::fmt::Display;

use hex::FromHexError;
use parth_core::{crypto::hash::traits::HashTo4Felts, pgoldilocks::QHashOut};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::PrimeField64},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::PoseidonGoldilocksConfig,
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_plonky2_basic_helpers::builder::verify::CircuitBuilderVerifyProofHelpers;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::to_string as json;
use serde_with::serde_as;
use plonky2x::backend::wrapper::wrap::WrappedCircuit;
use plonky2x::frontend::builder::CircuitBuilder as WrapperBuilder;
use plonky2x::prelude::DefaultParameters;

use crate::{
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    simple_wrapper::dynamic::SimpleWrapperDynamic,
};

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug, Eq, Hash, PartialOrd, Ord)]
pub struct Serialized2DFeltBN254(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 32]);
impl Default for Serialized2DFeltBN254 {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

impl Serialized2DFeltBN254 {
    pub fn from_hex_string(s: &str) -> Result<Self, FromHexError> {
        let bytes = hex::decode(s)?;
        assert_eq!(bytes.len(), 32);
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.0)
    }
    pub fn rand() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Serialized2DFeltBN254(bytes)
    }
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&x| x == 0)
    }
    pub fn from_slice(data: &[u8]) -> Self {
        let mut array = [0u8; 32];
        array.copy_from_slice(data);
        Self(array)
    }
}

impl Display for Serialized2DFeltBN254 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl TryFrom<&str> for Serialized2DFeltBN254 {
    type Error = FromHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Serialized2DFeltBN254::from_hex_string(value)
    }
}
impl TryFrom<String> for Serialized2DFeltBN254 {
    type Error = FromHexError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Serialized2DFeltBN254::from_hex_string(&value)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Hash, Ord, PartialOrd, Eq)]
pub struct UncompressedGroth16ProofData {
    pub pi_a: [String; 2],
    pub pi_b: [[String; 2]; 2],
    pub pi_c: [String; 2],
    pub public_inputs: [String; 2],
}

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = GoldilocksField;

#[derive(Debug)]
pub struct SharedGroth16Wrapper {
    pub wrapped_circuit: WrappedCircuit<DefaultParameters, gnark_plonky2_wrapper::parameters::Groth16WrapperParameters, D>,
    pub keystore_path: String,
}

impl SharedGroth16Wrapper {
    pub fn new(circuit_data: CircuitData<F, C, D>, keystore_path: String) -> Self {
        let wrapper_builder = WrapperBuilder::<DefaultParameters, D>::new();
        let mut circuit = wrapper_builder.build();
        circuit.data = circuit_data;
        let wrapped_circuit = WrappedCircuit::<
            DefaultParameters,
            gnark_plonky2_wrapper::parameters::Groth16WrapperParameters,
            D,
        >::build(circuit);
        Self {
            wrapped_circuit,
            keystore_path,
        }
    }

    pub fn prove_groth16(
        &self,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
        save_wrapped_data_path: Option<&str>,
    ) -> anyhow::Result<UncompressedGroth16ProofData> {
        let wrapped_output = self.wrapped_circuit.prove(inner_proof)?;
        if let Some(path) = save_wrapped_data_path {
            wrapped_output.save(path)?;
        }

        let (proof_string, vk_string) = gnark_plonky2_verifier_ffi::generate_groth16_proof(
            &json(&wrapped_output.common_data)?,
            &json(&wrapped_output.proof)?,
            &json(&wrapped_output.verifier_data)?,
            &self.keystore_path,
        );
        if proof_string.starts_with("error:") {
            anyhow::bail!("generate_groth16_proof failed: {}", proof_string);
        }
        if vk_string.starts_with("error:") {
            anyhow::bail!("generate_groth16_proof failed: {}", vk_string);
        }

        let proof_data = serde_json::from_str::<UncompressedGroth16ProofData>(&proof_string)?;
        Ok(proof_data)
    }
}

fn bridge_wrap_public_inputs_keccak_bytes(public_inputs: &[F]) -> Vec<u8> {
    public_inputs
        .iter()
        .enumerate()
        .flat_map(|(i, x)| {
            if (4..20).contains(&i) {
                let paired_index = if i % 2 == 0 { i + 1 } else { i - 1 };
                (public_inputs[paired_index].to_noncanonical_u64() as u32).to_be_bytes().to_vec()
            } else {
                x.to_noncanonical_u64().to_be_bytes().to_vec()
            }
        })
        .collect()
}

#[derive(Debug)]
pub struct BridgeWrapCircuit {
    pub wrapper: SimpleWrapperDynamic<C, D>,
}

impl BridgeWrapCircuit {
    pub fn new(common_data: &CommonCircuitData<F, D>, fingerprint: QHashOut<F>, inner_verifier_data_cap_height: usize) -> Self {
        Self {
            wrapper: SimpleWrapperDynamic::<C, D>::new(
                common_data,
                fingerprint,
                inner_verifier_data_cap_height,
                |i| if i >= 4 && i < 20 { 32 } else { 64 },
            ),
        }
    }

    pub fn into_shared_groth16_wrapper(self, keystore_path: String) -> SharedGroth16Wrapper {
        SharedGroth16Wrapper::new(self.wrapper.circuit_data, keystore_path)
    }

    pub fn prove_groth16_with_shared_wrapper(
        &self,
        shared_wrapper: &SharedGroth16Wrapper,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<UncompressedGroth16ProofData> {
        tracing::info!(
            "bridge_wrap pre-wrap PI count: {}",
            self.wrapper.circuit_data.common.num_public_inputs
        );
        let wrapper_proof = self.wrapper.prove_base(inner_proof, verifier_data)?;
        tracing::info!(
            "bridge_wrap wrapper proof PI count: {}",
            wrapper_proof.public_inputs.len()
        );
        let public_inputs_hash = QHashOut::from_4_felts_slice(&inner_proof.public_inputs[20..24]);

        let flat_bytes = bridge_wrap_public_inputs_keccak_bytes(&inner_proof.public_inputs);
        let mut keccak = tiny_keccak::Keccak::v256();
        let mut hash = [0u8; 32];
        tiny_keccak::Hasher::update(&mut keccak, &flat_bytes);
        tiny_keccak::Hasher::finalize(keccak, &mut hash);
        tracing::info!("prove_groth16_with_shared_wrapper public inouts: keccak256: 0x{}", hex::encode(hash));

        shared_wrapper.prove_groth16(
            &wrapper_proof,
            Some(&format!("/tmp/plonky2_proof/{}", public_inputs_hash)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::bridge_wrap_public_inputs_keccak_bytes;
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

    #[test]
    fn bridge_wrap_keccak_bytes_pair_swap_tree_root_limbs() {
        let public_inputs = (0u64..26)
            .map(GoldilocksField::from_canonical_u64)
            .collect::<Vec<_>>();
        let bytes = bridge_wrap_public_inputs_keccak_bytes(&public_inputs);

        assert_eq!(&bytes[0..8], &0u64.to_be_bytes());
        assert_eq!(&bytes[8..16], &1u64.to_be_bytes());
        assert_eq!(&bytes[16..24], &2u64.to_be_bytes());
        assert_eq!(&bytes[24..32], &3u64.to_be_bytes());

        // Tree-root limbs [4..20) are serialized as adjacent swapped u32 pairs.
        assert_eq!(&bytes[32..36], &5u32.to_be_bytes());
        assert_eq!(&bytes[36..40], &4u32.to_be_bytes());
        assert_eq!(&bytes[40..44], &7u32.to_be_bytes());
        assert_eq!(&bytes[44..48], &6u32.to_be_bytes());
        assert_eq!(&bytes[80..84], &17u32.to_be_bytes());
        assert_eq!(&bytes[84..88], &16u32.to_be_bytes());
        assert_eq!(&bytes[88..92], &19u32.to_be_bytes());
        assert_eq!(&bytes[92..96], &18u32.to_be_bytes());

        assert_eq!(&bytes[96..104], &20u64.to_be_bytes());
        assert_eq!(&bytes[120..128], &23u64.to_be_bytes());
        assert_eq!(&bytes[128..136], &24u64.to_be_bytes());
        assert_eq!(&bytes[136..144], &25u64.to_be_bytes());
    }
}

#[derive(Debug)]
pub struct DepositBatchWrapCircuit {
    pub proof_target: ProofWithPublicInputsTarget<D>,
    pub verifier_data_target: VerifierCircuitTarget,
    pub circuit_data: CircuitData<F, C, D>,
}

impl DepositBatchWrapCircuit {
    pub fn new(common_data: &CommonCircuitData<F, D>, fingerprint: QHashOut<F>, inner_verifier_data_cap_height: usize) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let proof_target = builder.add_virtual_proof_with_pis(common_data);
        let verifier_data_target = builder.add_virtual_verifier_data(inner_verifier_data_cap_height);
        builder.verify_proof::<C>(&proof_target, &verifier_data_target, common_data);

        let expected_fingerprint = builder.constant_hash(fingerprint.into());
        let actual_fingerprint =
            builder.get_circuit_fingerprint::<<C as plonky2::plonk::config::GenericConfig<D>>::Hasher>(&verifier_data_target);
        builder.connect_hashes(expected_fingerprint, actual_fingerprint);

        // gnark worker groups every 64 consecutive LE bits into one u64 limb and
        // serialises with BigEndian.PutUint64, which places the HIGH 32-bit word
        // first.  To make the resulting keccak input match the natural word order
        // (word[0]_BE, word[1]_BE, …) we register each pair in SWAPPED order:
        // [word1_bits, word0_bits] so that gnark reconstructs limb = word1 + word0<<32
        // and BE serialisation yields [word0_BE, word1_BE].
        for pair in proof_target.public_inputs.chunks(2) {
            if pair.len() == 2 {
                let bits1 = builder.split_le(pair[1], 32);
                for bit in &bits1 {
                    builder.register_public_input(bit.target);
                }
                let bits0 = builder.split_le(pair[0], 32);
                for bit in &bits0 {
                    builder.register_public_input(bit.target);
                }
            } else {
                // Odd trailing element: register normally, then pad to 64 bits.
                let bits = builder.split_le(pair[0], 32);
                for bit in &bits {
                    builder.register_public_input(bit.target);
                }
                let zero = builder.zero();
                let pad_bits = builder.split_le(zero, 32);
                for bit in &pad_bits {
                    builder.register_public_input(bit.target);
                }
            }
        }

        let circuit_data = builder.build::<C>();
        Self {
            proof_target,
            verifier_data_target,
            circuit_data,
        }
    }

    pub fn into_shared_groth16_wrapper(self, keystore_path: String) -> SharedGroth16Wrapper {
        SharedGroth16Wrapper::new(self.circuit_data, keystore_path)
    }

    pub fn prove_groth16_with_shared_wrapper(
        &self,
        shared_wrapper: &SharedGroth16Wrapper,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<UncompressedGroth16ProofData> {
        tracing::info!(
            "deposit_batch pre-wrap PI count: {}, inner proof PI count: {}",
            self.circuit_data.common.num_public_inputs,
            inner_proof.public_inputs.len()
        );
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.proof_target, inner_proof)?;
        pw.set_verifier_data_target(&self.verifier_data_target, verifier_data)?;
        let wrapper_proof = self.circuit_data.prove(pw)?;
        tracing::info!(
            "deposit_batch wrapper proof PI count: {}",
            wrapper_proof.public_inputs.len()
        );
        let public_inputs_hash = QHashOut::from_4_felts_slice(&inner_proof.public_inputs[0..4]);

        let mut flat_bytes: Vec<u8> = inner_proof
            .public_inputs
            .iter()
            .flat_map(|x| (x.to_noncanonical_u64() as u32).to_be_bytes().to_vec())
            .collect();
        if inner_proof.public_inputs.len() % 2 == 1 {
            flat_bytes.extend_from_slice(&0u32.to_be_bytes());
        }
        let mut keccak = tiny_keccak::Keccak::v256();
        let mut hash = [0u8; 32];
        tiny_keccak::Hasher::update(&mut keccak, &flat_bytes);
        tiny_keccak::Hasher::finalize(keccak, &mut hash);
        tracing::info!("deposit_batch prove_groth16_with_shared_wrapper public inputs: keccak256: 0x{}", hex::encode(hash));

        shared_wrapper.prove_groth16(
            &wrapper_proof,
            Some(&format!("/tmp/plonky2_proof/{}", public_inputs_hash)),
        )
    }
}

#[derive(Debug)]
pub struct WithdrawalClaimWrapCircuit {
    pub proof_target: ProofWithPublicInputsTarget<D>,
    pub verifier_data_target: VerifierCircuitTarget,
    pub circuit_data: CircuitData<F, C, D>,
}

impl WithdrawalClaimWrapCircuit {
    pub fn new(common_data: &CommonCircuitData<F, D>, fingerprint: QHashOut<F>, inner_verifier_data_cap_height: usize) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let proof_target = builder.add_virtual_proof_with_pis(common_data);
        let verifier_data_target = builder.add_virtual_verifier_data(inner_verifier_data_cap_height);
        builder.verify_proof::<C>(&proof_target, &verifier_data_target, common_data);

        let expected_fingerprint = builder.constant_hash(fingerprint.into());
        let actual_fingerprint =
            builder.get_circuit_fingerprint::<<C as plonky2::plonk::config::GenericConfig<D>>::Hasher>(&verifier_data_target);
        builder.connect_hashes(expected_fingerprint, actual_fingerprint);

        // Swap pair order so gnark's 64-bit BE limb grouping produces natural word order.
        // See DepositBatchWrapCircuit::new for detailed explanation.
        for pair in proof_target.public_inputs.chunks(2) {
            if pair.len() == 2 {
                let bits1 = builder.split_le(pair[1], 32);
                for bit in &bits1 {
                    builder.register_public_input(bit.target);
                }
                let bits0 = builder.split_le(pair[0], 32);
                for bit in &bits0 {
                    builder.register_public_input(bit.target);
                }
            } else {
                let bits = builder.split_le(pair[0], 32);
                for bit in &bits {
                    builder.register_public_input(bit.target);
                }
                let zero = builder.zero();
                let pad_bits = builder.split_le(zero, 32);
                for bit in &pad_bits {
                    builder.register_public_input(bit.target);
                }
            }
        }

        let circuit_data = builder.build::<C>();
        Self {
            proof_target,
            verifier_data_target,
            circuit_data,
        }
    }

    pub fn into_shared_groth16_wrapper(self, keystore_path: String) -> SharedGroth16Wrapper {
        SharedGroth16Wrapper::new(self.circuit_data, keystore_path)
    }

    pub fn prove_groth16_with_shared_wrapper(
        &self,
        shared_wrapper: &SharedGroth16Wrapper,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<UncompressedGroth16ProofData> {
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.proof_target, inner_proof)?;
        pw.set_verifier_data_target(&self.verifier_data_target, verifier_data)?;
        let wrapper_proof = self.circuit_data.prove(pw)?;
        let public_inputs_hash = QHashOut::from_4_felts_slice(&inner_proof.public_inputs[0..4]);

        let flat_bytes: Vec<u8> = inner_proof
            .public_inputs
            .iter()
            .flat_map(|x| (x.to_noncanonical_u64() as u32).to_be_bytes().to_vec())
            .collect();
        let mut keccak = tiny_keccak::Keccak::v256();
        let mut hash = [0u8; 32];
        tiny_keccak::Hasher::update(&mut keccak, &flat_bytes);
        tiny_keccak::Hasher::finalize(keccak, &mut hash);
        tracing::info!(
            "withdrawal_claim prove_groth16_with_shared_wrapper inner public inputs keccak (Bridge calldata order, pre-gnark packing): 0x{}",
            hex::encode(hash)
        );

        shared_wrapper.prove_groth16(
            &wrapper_proof,
            Some(&format!("/tmp/plonky2_proof/{}", public_inputs_hash)),
        )
    }
}
