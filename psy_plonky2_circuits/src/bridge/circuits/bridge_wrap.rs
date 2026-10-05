pub use std::fmt::Display;

use hex::FromHexError;
use parth_core::{crypto::hash::traits::HashTo4Felts, pgoldilocks::QHashOut};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::PrimeField64},
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
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

pub use gnark_plonky2_verifier_ffi::DigestArtifact;
use plonky2::field::types::Field;
use parth_core::crypto::hash::traits::ToU64x4;
use psy_common_circuit::serialization::PsyGateSerializer;
use psy_crypto::hash::core::sha256::CoreSha256Hasher;

const OPENING_DIGEST_PI_LEN: usize = 12;
const OPENING_DIGEST_BITS: usize = 256;
const WITHDRAWAL_PUBLICATION_PI_LEN: usize = 28;
const WITHDRAWAL_PUBLICATION_BITS: usize = 768;
const DIGEST_WORD_BITS: usize = 32;
const PUBLICATION_DIGEST_WORDS: usize = 8;

fn digest_artifact_statement(artifact: DigestArtifact) -> (usize, usize) {
    match artifact {
        DigestArtifact::DepositAggregate | DigestArtifact::RewardAggregate => (OPENING_DIGEST_PI_LEN, OPENING_DIGEST_BITS),
        DigestArtifact::WithdrawalAggregate => (WITHDRAWAL_PUBLICATION_PI_LEN, WITHDRAWAL_PUBLICATION_BITS),
    }
}

fn digest_artifact_prefix(artifact: DigestArtifact) -> [u64; 4] {
    match artifact {
        DigestArtifact::DepositAggregate => [1, 11, 1, 0],
        DigestArtifact::WithdrawalAggregate => [1, 7, 2, 0],
        DigestArtifact::RewardAggregate => [1, 7, 3, 0],
    }
}

fn register_digest_bits(builder: &mut CircuitBuilder<F, D>, words: &[Target]) {
    for word in words {
        let bits = builder.split_le(*word, DIGEST_WORD_BITS);
        for bit in bits.into_iter().rev() { builder.register_public_input(bit.target); }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestBitsSources {
    pub node_source: String,
    pub native_source: String,
    pub plonky2_source: String,
    pub wrapper_source: String,
}

impl DigestBitsSources {
    pub fn validate(&self) -> anyhow::Result<()> {
        for source in [&self.node_source, &self.native_source, &self.plonky2_source, &self.wrapper_source] {
            let (hex, width) = source.strip_prefix("local:").map_or((source.as_str(), 40), |hex| (hex, 64));
            anyhow::ensure!(hex.len() == width && hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "invalid reviewed source identity");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DigestBitsIdentity {
    pub schema: u32,
    pub mode: String,
    pub artifact: u32,
    pub node_source: String,
    pub native_source: String,
    pub plonky2_source: String,
    pub wrapper_source: String,
    pub normalizer_fingerprint: [u64; 4],
    pub normalizer_common: String,
    pub normalizer_verifier: String,
    pub final_common_json: String,
    pub final_verifier_json: String,
}

impl DigestBitsIdentity {
    pub fn identity_hash(&self) -> anyhow::Result<String> {
        anyhow::ensure!(self.schema == 1 && self.mode == "DigestBits" && matches!(self.artifact, 1 | 2 | 3), "invalid DigestBits identity");
        DigestBitsSources { node_source: self.node_source.clone(), native_source: self.native_source.clone(), plonky2_source: self.plonky2_source.clone(), wrapper_source: self.wrapper_source.clone() }.validate()?;
        anyhow::ensure!(self.normalizer_fingerprint.iter().all(|limb| *limb < 0xffff_ffff_0000_0001), "noncanonical fingerprint");
        let mut bytes = b"PsyBridge/DigestBits/1".to_vec();
        bytes.extend(self.schema.to_be_bytes());
        bytes.extend(self.artifact.to_be_bytes());
        fn append(bytes: &mut Vec<u8>, value: &[u8]) {
            bytes.extend((value.len() as u64).to_be_bytes());
            bytes.extend(value);
        }
        for value in [&self.mode, &self.node_source, &self.native_source, &self.plonky2_source, &self.wrapper_source] { append(&mut bytes, value.as_bytes()); }
        for limb in self.normalizer_fingerprint { bytes.extend(limb.to_be_bytes()); }
        for value in [&self.normalizer_common, &self.normalizer_verifier] {
            let decoded = hex::decode(value)?;
            anyhow::ensure!(hex::encode(&decoded) == *value, "noncanonical identity hex");
            append(&mut bytes, &decoded);
        }
        append(&mut bytes, self.final_common_json.as_bytes());
        append(&mut bytes, self.final_verifier_json.as_bytes());
        Ok(hex::encode(CoreSha256Hasher::hash_bytes(&bytes).0))
    }
}

pub struct DigestBitsAdapter {
    pub circuit_data: CircuitData<F, C, D>,
    normalizer: ProofWithPublicInputsTarget<D>,
    artifact: DigestArtifact,
    normalizer_fingerprint: [u64; 4],
    normalizer_common: String,
    normalizer_verifier: String,
}

impl DigestBitsAdapter {
    pub fn build(artifact: DigestArtifact, common: &CommonCircuitData<F, D>, verifier: &VerifierOnlyCircuitData<C, D>) -> anyhow::Result<Self> {
        let (statement_len, digest_bits) = digest_artifact_statement(artifact);
        anyhow::ensure!(common.num_public_inputs == statement_len, "normalizer public input width mismatch");
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let normalizer = builder.add_virtual_proof_with_pis(common);
        let pinned_verifier = builder.constant_verifier_data(verifier);
        builder.verify_proof::<C>(&normalizer, &pinned_verifier, common);
        for (target, value) in normalizer.public_inputs[..4].iter().zip(digest_artifact_prefix(artifact)) {
            let constant = builder.constant(F::from_canonical_u64(value));
            builder.connect(*target, constant);
        }
        let digest_words = &normalizer.public_inputs[4..];
        anyhow::ensure!(digest_words.len() * DIGEST_WORD_BITS == digest_bits, "digest bit width mismatch");
        register_digest_bits(&mut builder, digest_words);
        let circuit_data = builder.build::<C>();
        anyhow::ensure!(circuit_data.common.num_public_inputs == digest_bits, "adapter digest width mismatch");
        Ok(Self {
            circuit_data, normalizer, artifact,
            normalizer_fingerprint: crate::proof_minifier::pm_core::get_circuit_fingerprint_generic_q::<D, F, C>(verifier).to_u64x4(),
            normalizer_common: hex::encode(common.to_bytes(&PsyGateSerializer).map_err(|error| anyhow::anyhow!("common serialization: {error:?}"))?),
            normalizer_verifier: hex::encode(verifier.to_bytes().map_err(|error| anyhow::anyhow!("verifier serialization: {error:?}"))?),
        })
    }

    pub fn prove(&self, proof: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (statement_len, _) = digest_artifact_statement(self.artifact);
        anyhow::ensure!(proof.public_inputs.len() == statement_len, "normalizer PI width mismatch");
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(&self.normalizer, proof)?;
        let proved = self.circuit_data.prove(witness)?;
        anyhow::ensure!(proved.public_inputs.len() == self.circuit_data.common.num_public_inputs, "adapter proof width mismatch");
        Ok(proved)
    }

    pub fn into_wrapper(self, sources: DigestBitsSources) -> anyhow::Result<DigestBitsWrapper> {
        sources.validate()?;
        let (_, digest_bits) = digest_artifact_statement(self.artifact);
        let shared = SharedGroth16Wrapper::new(self.circuit_data, String::new());
        let final_data = &shared.wrapped_circuit.wrapper_circuit.data;
        anyhow::ensure!(final_data.common.num_public_inputs == digest_bits, "final wrapper digest width mismatch");
        let identity = DigestBitsIdentity {
            schema: 1, mode: "DigestBits".into(), artifact: self.artifact as u32,
            node_source: sources.node_source, native_source: sources.native_source,
            plonky2_source: sources.plonky2_source, wrapper_source: sources.wrapper_source,
            normalizer_fingerprint: self.normalizer_fingerprint, normalizer_common: self.normalizer_common,
            normalizer_verifier: self.normalizer_verifier,
            final_common_json: json(&final_data.common)?, final_verifier_json: json(&final_data.verifier_only)?,
        };
        identity.identity_hash()?;
        Ok(DigestBitsWrapper { shared, artifact: self.artifact, identity })
    }
}

pub struct DigestBitsWrapper {
    shared: SharedGroth16Wrapper,
    artifact: DigestArtifact,
    identity: DigestBitsIdentity,
}

impl DigestBitsWrapper {
    pub fn identity(&self) -> &DigestBitsIdentity { &self.identity }

    pub fn setup(&self, artifact_dir: &str) -> anyhow::Result<()> {
        gnark_plonky2_verifier_ffi::setup_digest_bits(self.artifact, &json(&self.identity)?, artifact_dir)
            .map_err(|error| anyhow::anyhow!("DigestBits setup status {}: {}", error.status, error.message))
    }

    pub fn prove_groth16(&self, adapter_proof: &ProofWithPublicInputs<F, C, D>, artifact_dir: &str) -> anyhow::Result<UncompressedGroth16ProofData> {
        anyhow::ensure!(self.artifact != DigestArtifact::WithdrawalAggregate, "withdrawal publication requires six native public inputs");
        let (_, digest_bits) = digest_artifact_statement(self.artifact);
        let words = digest_bit_words::<2>(adapter_proof, digest_bits)?;
        let proof = self.prove_native(adapter_proof, artifact_dir)?;
        let decoded: UncompressedGroth16ProofData = serde_json::from_str(&proof)?;
        anyhow::ensure!(decode_digest_words(&decoded.public_inputs)? == words, "native digest halves mismatch");
        Ok(decoded)
    }

    pub fn prove_withdrawal_publication(&self, adapter_proof: &ProofWithPublicInputs<F, C, D>, artifact_dir: &str) -> anyhow::Result<WithdrawalPublicationProof> {
        anyhow::ensure!(self.artifact == DigestArtifact::WithdrawalAggregate, "not a withdrawal publication wrapper");
        let words = digest_bit_words::<6>(adapter_proof, WITHDRAWAL_PUBLICATION_BITS)?;
        let proof = self.prove_native(adapter_proof, artifact_dir)?;
        let decoded: WithdrawalPublicationProof = serde_json::from_str(&proof)?;
        anyhow::ensure!(decode_digest_words(&decoded.public_inputs)? == words, "native withdrawal publication words mismatch");
        Ok(decoded)
    }

    fn prove_native(&self, adapter_proof: &ProofWithPublicInputs<F, C, D>, artifact_dir: &str) -> anyhow::Result<String> {
        let output = self.shared.wrapped_circuit.prove(adapter_proof)?;
        let result = gnark_plonky2_verifier_ffi::generate_digest_bits_proof(self.artifact, &json(&self.identity)?, &json(&output.proof)?, artifact_dir)
            .map_err(|error| anyhow::anyhow!("DigestBits proving status {}: {}", error.status, error.message))?;
        Ok(result.proof_json)
    }
}

fn digest_bit_words<const N: usize>(adapter_proof: &ProofWithPublicInputs<F, C, D>, digest_bits: usize) -> anyhow::Result<[u128; N]> {
    anyhow::ensure!(digest_bits == N * 128 && adapter_proof.public_inputs.len() == digest_bits, "digest PI width mismatch");
    let mut words = [0u128; N];
    for (index, bit) in adapter_proof.public_inputs.iter().enumerate() {
        let bit = bit.to_canonical_u64();
        anyhow::ensure!(bit <= 1, "digest input is not Boolean");
        words[index / 128] = (words[index / 128] << 1) | u128::from(bit);
    }
    Ok(words)
}

fn decode_digest_words<const N: usize>(inputs: &[String; N]) -> anyhow::Result<[u128; N]> {
    let mut words = [0u128; N];
    for (word, decoded) in inputs.iter().zip(&mut words) {
        anyhow::ensure!(word.len() == 64 && word.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "native digest input must be 64 lowercase hexadecimal digits");
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(word, &mut bytes)?;
        anyhow::ensure!(bytes[..16] == [0; 16], "native digest input exceeds uint128");
        *decoded = u128::from_be_bytes(bytes[16..].try_into()?);
    }
    Ok(words)
}

fn decode_digest_bits_public_inputs(inputs: &[String; 2]) -> anyhow::Result<[u128; 2]> {
    decode_digest_words(inputs)
}

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

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Hash, Ord, PartialOrd, Eq)]
pub struct WithdrawalPublicationProof {
    pub pi_a: [String; 2],
    pub pi_b: [[String; 2]; 2],
    pub pi_c: [String; 2],
    pub public_inputs: [String; 6],
}

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = GoldilocksField;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalizeIdentity {
    pub schema: u32,
    pub chain_indices: Vec<u8>,
    pub final_common_json: String,
    pub final_verifier_json: String,
}

#[derive(Debug)]
pub struct SharedGroth16Wrapper {
    pub wrapped_circuit: WrappedCircuit<DefaultParameters, gnark_plonky2_wrapper::parameters::Groth16WrapperParameters, D>,
    pub keystore_path: String,
    finalize_identity: Option<FinalizeIdentity>,
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
            finalize_identity: None,
        }
    }

    pub fn setup_finalize(&self) -> anyhow::Result<()> {
        let identity = self.finalize_identity.as_ref().ok_or_else(|| anyhow::anyhow!("not a finalize wrapper"))?;
        gnark_plonky2_verifier_ffi::setup_finalize(&json(identity)?, &self.keystore_path)
            .map_err(|error| anyhow::anyhow!("finalize setup: {error}"))
    }

    pub fn validate_finalize_setup(&self) -> anyhow::Result<()> {
        let expected = self.finalize_identity.as_ref().ok_or_else(|| anyhow::anyhow!("not a finalize wrapper"))?;
        let json = gnark_plonky2_verifier_ffi::read_finalize_setup_identity(&self.keystore_path)
            .map_err(|error| anyhow::anyhow!("finalize identity: {error}"))?;
        let actual: FinalizeIdentity = serde_json::from_str(&json)?;
        anyhow::ensure!(&actual == expected, "finalize setup differs from source circuit/list identity");
        Ok(())
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
        if let Some(identity) = &self.finalize_identity {
            let result = gnark_plonky2_verifier_ffi::generate_finalize_proof(&json(identity)?, &json(&wrapped_output.proof)?, &self.keystore_path)
                .map_err(|error| anyhow::anyhow!("finalize proving: {error}"))?;
            return Ok(serde_json::from_str(&result.proof_json)?);
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

fn bridge_wrap_public_inputs_keccak_bytes(public_inputs: &[F], chain_count: usize) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!((1..=256).contains(&chain_count) && public_inputs.len() == 26 + 9 * chain_count, "finalize public input width mismatch");
    let mut bytes = Vec::with_capacity(144 + 72 * chain_count);
    for (i, input) in public_inputs.iter().enumerate() {
        let value = input.to_canonical_u64();
        if (4..20).contains(&i) {
            anyhow::ensure!(value <= u32::MAX as u64, "global root word exceeds u32");
            let paired_index = if i % 2 == 0 { i + 1 } else { i - 1 };
            let paired = u32::try_from(public_inputs[paired_index].to_canonical_u64())?;
            bytes.extend_from_slice(&paired.to_be_bytes());
        } else {
            if i == 24 || i == 25 || (i >= 26 && (i - 26) % 9 == 4) {
                anyhow::ensure!(value <= u32::MAX as u64, "finalize count exceeds u32");
            }
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
    Ok(bytes)
}

#[derive(Debug)]
pub struct BridgeWrapCircuit {
    pub wrapper: SimpleWrapperDynamic<C, D>,
    configured_chain_indices: Vec<u8>,
}

impl BridgeWrapCircuit {
    pub fn new(finalizer: &super::bridge_agg_final::BridgeAggFinalCircuit<C, D>) -> anyhow::Result<Self> {
        let configured_chain_indices = finalizer.configured_chain_indices();
        let common_data = &finalizer.circuit_data.common;
        anyhow::ensure!((1..=256).contains(&configured_chain_indices.len()) && configured_chain_indices.windows(2).all(|pair| pair[0] < pair[1]), "invalid finalize chain list");
        anyhow::ensure!(common_data.num_public_inputs == 26 + 9 * configured_chain_indices.len(), "finalize circuit width differs from chain list");
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let proof_target = builder.add_virtual_proof_with_pis(common_data);
        let verifier_data_target = builder.add_virtual_verifier_data(finalizer.circuit_data.verifier_only.constants_sigmas_cap.height());
        builder.verify_proof::<C>(&proof_target, &verifier_data_target, common_data);
        let expected = builder.constant_hash(finalizer.fingerprint.0);
        let actual = builder.get_circuit_fingerprint::<<C as plonky2::plonk::config::GenericConfig<D>>::Hasher>(&verifier_data_target);
        builder.connect_hashes(expected, actual);
        for (i, input) in proof_target.public_inputs.iter().enumerate() {
            let narrow = (4..20).contains(&i);
            let bits = builder.split_le(*input, if narrow { 32 } else { 64 });
            if !narrow {
                let low = builder.le_sum(bits[..32].iter());
                let high = builder.le_sum(bits[32..].iter());
                let max = builder.constant(F::from_canonical_u64(u32::MAX as u64));
                let high_max = builder.is_equal(high, max);
                let overflow = builder.mul(high_max.target, low);
                builder.assert_zero(overflow);
                if i == 24 || i == 25 || (i >= 26 && (i - 26) % 9 == 4) { builder.assert_zero(high); }
            }
            for bit in bits { builder.register_public_input(bit.target); }
        }
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic::<D, F, C>(&circuit_data.verifier_only));
        Ok(Self {
            wrapper: SimpleWrapperDynamic { proof_target, verifier_data_target, circuit_data, fingerprint },
            configured_chain_indices: configured_chain_indices.to_vec(),
        })
    }

    pub fn into_shared_groth16_wrapper(self, keystore_path: String) -> SharedGroth16Wrapper {
        let mut shared = SharedGroth16Wrapper::new(self.wrapper.circuit_data, keystore_path);
        let final_data = &shared.wrapped_circuit.wrapper_circuit.data;
        shared.finalize_identity = Some(FinalizeIdentity {
            schema: 1,
            chain_indices: self.configured_chain_indices,
            final_common_json: json(&final_data.common).expect("final common data serialization"),
            final_verifier_json: json(&final_data.verifier_only).expect("final verifier data serialization"),
        });
        shared
    }

    fn prove_wrapper(
        &self,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, String)> {
        let flat_bytes = bridge_wrap_public_inputs_keccak_bytes(&inner_proof.public_inputs, self.configured_chain_indices.len())?;
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
        let mut keccak = tiny_keccak::Keccak::v256();
        let mut hash = [0u8; 32];
        tiny_keccak::Hasher::update(&mut keccak, &flat_bytes);
        tiny_keccak::Hasher::finalize(keccak, &mut hash);
        tracing::info!("prove_groth16 public inputs: keccak256: 0x{}", hex::encode(hash));
        Ok((wrapper_proof, format!("/tmp/plonky2_proof/{}", public_inputs_hash)))
    }

    pub fn prove_groth16_with_shared_wrapper(
        &self,
        shared_wrapper: &SharedGroth16Wrapper,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<UncompressedGroth16ProofData> {
        anyhow::ensure!(shared_wrapper.finalize_identity.as_ref().map(|identity| identity.chain_indices.as_slice()) == Some(self.configured_chain_indices.as_slice()), "finalize wrapper chain list mismatch");
        let (wrapper_proof, path) = self.prove_wrapper(verifier_data, inner_proof)?;
        shared_wrapper.prove_groth16(&wrapper_proof, Some(&path))
    }

    pub fn prove_groth16(
        self,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
        keystore_path: String,
    ) -> anyhow::Result<UncompressedGroth16ProofData> {
        let (wrapper_proof, path) = self.prove_wrapper(verifier_data, inner_proof)?;
        let shared = self.into_shared_groth16_wrapper(keystore_path);
        shared.prove_groth16(&wrapper_proof, Some(&path))
    }
}

#[cfg(test)]
mod tests {
    use super::bridge_wrap_public_inputs_keccak_bytes;
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

    #[test]
    fn native_digest_inputs_decode_canonical_uint128_words() {
        use super::decode_digest_bits_public_inputs;
        let words = [
            "000000000000000000000000000000008123456789abcdef0123456789abcdef".to_owned(),
            "00000000000000000000000000000000ffffffffffffffffffffffffffffffff".to_owned(),
        ];
        let expected = [0x8123456789abcdef0123456789abcdefu128, u128::MAX];
        assert_eq!(decode_digest_bits_public_inputs(&words).unwrap(), expected);
        assert_eq!(decode_digest_bits_public_inputs(&["0".repeat(64), format!("{:064x}", 1u128)]).unwrap(), [0, 1]);
        let swapped = [words[1].clone(), words[0].clone()];
        assert_ne!(decode_digest_bits_public_inputs(&swapped).unwrap(), expected);
        let mut changed = words.clone();
        changed[0].replace_range(63..64, "0");
        assert_ne!(decode_digest_bits_public_inputs(&changed).unwrap(), expected);
        for invalid in [expected[0].to_string(), format!("0x{}", words[0]), words[0].to_uppercase(), "0".repeat(63), "0".repeat(65), format!("1{}", "0".repeat(63)), format!("{}g", "0".repeat(63))] {
            assert!(decode_digest_bits_public_inputs(&[invalid, words[1].clone()]).is_err());
        }
    }

    #[test]
    fn withdrawal_publication_words_reject_wrong_count_order_and_high_bits() {
        use super::{decode_digest_words, WithdrawalPublicationProof};
        let word = |value: u128| format!("{value:064x}");
        let values = [1u128, 2, 3, 4, 5, u128::MAX];
        let words = std::array::from_fn(|index| word(values[index]));
        assert_eq!(decode_digest_words::<6>(&words).unwrap(), values);
        let mut swapped = words.clone();
        swapped.swap(0, 5);
        assert_ne!(decode_digest_words::<6>(&swapped).unwrap(), values);
        let mut high = words.clone();
        high[2] = format!("01{}", "0".repeat(62));
        assert!(decode_digest_words::<6>(&high).is_err());
        let curve = ["0".repeat(64), "0".repeat(64)];
        let proof = WithdrawalPublicationProof { pi_a: curve.clone(), pi_b: [curve.clone(), curve.clone()], pi_c: curve.clone(), public_inputs: words.clone() };
        let encoded = serde_json::to_string(&proof).unwrap();
        assert_eq!(serde_json::from_str::<WithdrawalPublicationProof>(&encoded).unwrap(), proof);
        for count in [0, 1, 2, 5, 7] {
            let wrong = serde_json::json!({"pi_a": [&curve[0], &curve[1]], "pi_b": [[&curve[0], &curve[1]], [&curve[0], &curve[1]]], "pi_c": [&curve[0], &curve[1]], "Commitments": "", "CommitmentPok": "0".repeat(128), "public_inputs": vec!["0".repeat(64); count]});
            assert!(serde_json::from_value::<WithdrawalPublicationProof>(wrong).is_err(), "accepted {count} publication words");
        }
        let native = serde_json::json!({"pi_a": [&curve[0], &curve[1]], "pi_b": [[&curve[0], &curve[1]], [&curve[0], &curve[1]]], "pi_c": [&curve[0], &curve[1]], "Commitments": "", "CommitmentPok": "0".repeat(128), "public_inputs": words});
        let decoded: WithdrawalPublicationProof = serde_json::from_value(native).unwrap();
        assert_eq!(decoded, proof);
        assert_eq!(decode_digest_words::<6>(&decoded.public_inputs).unwrap(), values);
    }

    #[test]
    fn digest_adapter_pins_prefix_source_and_bit_order() {
        use super::{C, D, DigestArtifact, DigestBitsAdapter, F};
        use plonky2::{iop::witness::{PartialWitness, WitnessWrite}, plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig}};
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let inputs = builder.add_virtual_target_arr::<12>();
        builder.register_public_inputs(&inputs);
        let source = builder.build::<C>();
        let mut wrong_width = source.common.clone();
        wrong_width.num_public_inputs = 26;
        assert!(DigestBitsAdapter::build(DigestArtifact::DepositAggregate, &wrong_width, &source.verifier_only).is_err());
        let words = [0x80000001u32, 0xffffffff, 0, 0x01234567, 0x89abcdef, 1, 0xaaaaaaaa, 0x55555555];
        let make_proof = |prefix: [u64; 4], high_word: bool| {
            let mut witness = PartialWitness::new();
            for (index, target) in inputs.iter().enumerate() {
                let value = match index {
                    0..=3 => prefix[index],
                    4 if high_word => 1u64 << 32,
                    4..=11 => u64::from(words[index - 4]),
                    _ => 0,
                };
                witness.set_target(*target, F::from_canonical_u64(value)).unwrap();
            }
            source.prove(witness).unwrap()
        };
        let expected: Vec<_> = words.iter().flat_map(|word| (0..32).rev().map(move |bit| F::from_canonical_u64(u64::from((word >> bit) & 1)))).collect();
        for (artifact, prefix) in [
            (DigestArtifact::DepositAggregate, [1, 11, 1, 0]),
            (DigestArtifact::RewardAggregate, [1, 7, 3, 0]),
        ] {
            let adapter = DigestBitsAdapter::build(artifact, &source.common, &source.verifier_only).unwrap();
            let proof = adapter.prove(&make_proof(prefix, false)).unwrap();
            assert_eq!(proof.public_inputs, expected);
            adapter.circuit_data.verify(proof).unwrap();
            for index in 0..4 {
                let mut wrong_prefix = prefix;
                wrong_prefix[index] += 1;
                assert!(adapter.prove(&make_proof(wrong_prefix, false)).is_err());
            }
            if artifact != DigestArtifact::DepositAggregate {
                assert!(adapter.prove(&make_proof([1, 11, prefix[2], 0], false)).is_err());
            }
            assert!(adapter.prove(&make_proof(prefix, true)).is_err());
            let mut wrong_verifier = source.verifier_only.clone();
            wrong_verifier.circuit_digest.elements[0] += F::ONE;
            let wrong_adapter = DigestBitsAdapter::build(artifact, &source.common, &wrong_verifier).unwrap();
            assert!(wrong_adapter.prove(&make_proof(prefix, false)).is_err());
        }
    }

    #[test]
    fn withdrawal_publication_adapter_exposes_three_digests() {
        use super::{C, D, DIGEST_WORD_BITS, DigestArtifact, DigestBitsAdapter, F, PUBLICATION_DIGEST_WORDS, WITHDRAWAL_PUBLICATION_BITS};
        use plonky2::{iop::witness::{PartialWitness, WitnessWrite}, plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig}};
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let inputs = builder.add_virtual_target_arr::<28>();
        builder.register_public_inputs(&inputs);
        let source = builder.build::<C>();
        for width in [12, 26] {
            let mut wrong = source.common.clone();
            wrong.num_public_inputs = width;
            assert!(DigestBitsAdapter::build(DigestArtifact::WithdrawalAggregate, &wrong, &source.verifier_only).is_err());
        }
        assert!(DigestBitsAdapter::build(DigestArtifact::DepositAggregate, &source.common, &source.verifier_only).is_err());
        assert!(DigestBitsAdapter::build(DigestArtifact::RewardAggregate, &source.common, &source.verifier_only).is_err());
        let words: [u32; 24] = std::array::from_fn(|index| 0x0100_0000u32.wrapping_mul(index as u32 + 1).wrapping_add(0x89ab_cdef));
        let make_proof = |prefix: [u64; 4], mutation: Option<(usize, u64)>| {
            let mut witness = PartialWitness::new();
            for (index, target) in inputs.iter().enumerate() {
                let mut value = if index < 4 { prefix[index] } else { u64::from(words[index - 4]) };
                if let Some((word, replacement)) = mutation {
                    if index == word { value = replacement; }
                }
                witness.set_target(*target, F::from_canonical_u64(value)).unwrap();
            }
            source.prove(witness).unwrap()
        };
        let adapter = DigestBitsAdapter::build(DigestArtifact::WithdrawalAggregate, &source.common, &source.verifier_only).unwrap();
        assert_eq!(adapter.circuit_data.common.num_public_inputs, WITHDRAWAL_PUBLICATION_BITS);
        let proof = adapter.prove(&make_proof([1, 7, 2, 0], None)).unwrap();
        let digest_bits = |words: &[u32]| -> Vec<_> {
            words.iter().flat_map(|word| (0..32).rev().map(move |bit| F::from_canonical_u64(u64::from((*word >> bit) & 1)))).collect::<Vec<_>>()
        };
        let expected = digest_bits(&words);
        assert_eq!(proof.public_inputs.len(), WITHDRAWAL_PUBLICATION_BITS);
        assert_eq!(proof.public_inputs, expected);
        let native_words = super::digest_bit_words::<6>(&proof, WITHDRAWAL_PUBLICATION_BITS).unwrap();
        let packed = words.chunks(4).map(|chunk| chunk.iter().fold(0u128, |word, limb| (word << 32) | u128::from(*limb))).collect::<Vec<_>>();
        assert_eq!(native_words.as_slice(), packed.as_slice());
        let mut non_boolean = proof.clone();
        non_boolean.public_inputs[127] = F::from_canonical_u64(2);
        assert!(super::digest_bit_words::<6>(&non_boolean, WITHDRAWAL_PUBLICATION_BITS).is_err());
        for digest in 0..3 {
            let word_start = digest * PUBLICATION_DIGEST_WORDS;
            let bit_start = word_start * DIGEST_WORD_BITS;
            assert_eq!(
                &proof.public_inputs[bit_start..bit_start + PUBLICATION_DIGEST_WORDS * DIGEST_WORD_BITS],
                digest_bits(&words[word_start..word_start + PUBLICATION_DIGEST_WORDS]).as_slice(),
            );
        }
        adapter.circuit_data.verify(proof.clone()).unwrap();
        let mut mutated = proof;
        mutated.public_inputs[0] = if mutated.public_inputs[0] == F::ZERO { F::ONE } else { F::ZERO };
        assert!(adapter.circuit_data.verify(mutated).is_err());
        for index in 0..4 {
            let mut prefix = [1u64, 7, 2, 0];
            prefix[index] += 1;
            assert!(adapter.prove(&make_proof(prefix, None)).is_err());
        }
        for word in [4usize, 11, 12, 19, 20, 27] {
            let replacement = words[word - 4].wrapping_add(1);
            let changed = adapter.prove(&make_proof([1, 7, 2, 0], Some((word, u64::from(replacement))))).unwrap();
            let mut changed_words = words;
            changed_words[word - 4] = replacement;
            let changed_bits = digest_bits(&changed_words);
            assert_eq!(changed.public_inputs, changed_bits);
            assert_ne!(changed.public_inputs, expected);
            adapter.circuit_data.verify(changed).unwrap();
            assert!(adapter.prove(&make_proof([1, 7, 2, 0], Some((word, 1u64 << 32)))).is_err());
        }
        let mut wrong_verifier = source.verifier_only.clone();
        wrong_verifier.circuit_digest.elements[0] += F::ONE;
        let wrong_adapter = DigestBitsAdapter::build(DigestArtifact::WithdrawalAggregate, &source.common, &wrong_verifier).unwrap();
        assert!(wrong_adapter.prove(&make_proof([1, 7, 2, 0], None)).is_err());
    }

    #[test]
    fn digest_setup_identity_binds_family_and_source() {
        use super::DigestBitsIdentity;
        let mut identity = DigestBitsIdentity {
            schema: 1, mode: "DigestBits".into(), artifact: 1,
            node_source: "1".repeat(40), native_source: "2".repeat(40),
            plonky2_source: "3".repeat(40), wrapper_source: "4".repeat(40),
            normalizer_fingerprint: [1, 2, 3, 4], normalizer_common: "01".into(),
            normalizer_verifier: "02".into(), final_common_json: "{}".into(), final_verifier_json: "{}".into(),
        };
        let mut hashes = std::collections::HashSet::new();
        for artifact in [1, 2, 3] {
            identity.artifact = artifact;
            assert!(hashes.insert(identity.identity_hash().unwrap()));
        }
        let original = identity.identity_hash().unwrap();
        identity.normalizer_verifier = "03".into();
        assert_ne!(identity.identity_hash().unwrap(), original);
        for artifact in [0, 4] {
            identity.artifact = artifact;
            assert!(identity.identity_hash().is_err());
        }
    }

    #[test]
    fn bridge_wrap_keccak_bytes_pair_swap_tree_root_limbs() {
        let public_inputs = (0u64..44)
            .map(GoldilocksField::from_canonical_u64)
            .collect::<Vec<_>>();
        let bytes = bridge_wrap_public_inputs_keccak_bytes(&public_inputs, 2).unwrap();

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

        // Checkpoint metadata [20..26) remains full u64 limbs (no pair-swap).
        assert_eq!(&bytes[96..104], &20u64.to_be_bytes());
        assert_eq!(&bytes[120..128], &23u64.to_be_bytes());
        assert_eq!(&bytes[128..136], &24u64.to_be_bytes());
        assert_eq!(&bytes[136..144], &25u64.to_be_bytes());
        assert_eq!(bytes.len(), 144 + 72 * 2);
        for (ordinal, value) in (26u64..44).enumerate() {
            assert_eq!(&bytes[144 + ordinal * 8..152 + ordinal * 8], &value.to_be_bytes());
        }
        assert!(bridge_wrap_public_inputs_keccak_bytes(&public_inputs, 1).is_err());
        assert!(bridge_wrap_public_inputs_keccak_bytes(&public_inputs[..26], 0).is_err());
        for index in [4, 24, 25, 30, 39] {
            let mut invalid = public_inputs.clone();
            invalid[index] = GoldilocksField::from_canonical_u64(1u64 << 32);
            assert!(bridge_wrap_public_inputs_keccak_bytes(&invalid, 2).is_err());
        }
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
