pub use std::fmt::Display;

use hex::FromHexError;
use parth_core::{crypto::hash::traits::HashTo4Felts, pgoldilocks::QHashOut};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::PrimeField64},
    hash::poseidon::PoseidonHash,
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{GenericHashOut, Hasher, PoseidonGoldilocksConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use plonky2x::backend::wrapper::wrap::WrappedCircuit;
use plonky2x::frontend::builder::CircuitBuilder as WrapperBuilder;
use plonky2x::prelude::DefaultParameters;
use psy_plonky2_basic_helpers::builder::verify::CircuitBuilderVerifyProofHelpers;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::to_string as json;
use serde_with::serde_as;

use crate::{
    bridge::circuits::bridge_aggregate::bridge_aggregate_pi_len,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
};
use gnark_plonky2_wrapper::plonky2_config::PoseidonBN254Hash;

use plonky2::field::types::Field;
use psy_common_circuit::serialization::PsyGateSerializer;
use psy_crypto::hash::core::sha256::CoreSha256Hasher;
use psy_client_common::traits::to_qfelts::ToQFelts;
use psy_client_data::qdata::contract::PsyContractLeaf;

use super::bridge_claim::BridgeTokenPolicy;

const OPENING_PREFIX: [u64; 4] = [4, 12, 0, 0];
const DEPOSIT_CAPACITY: u32 = 32;
const WITHDRAWAL_CAPACITY: u32 = 32;
const REWARD_CAPACITY: u32 = 32;
const CONTRACT_LEAF_DOMAIN: u64 = 0x434c_5633;
const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

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

fn canonical_limbs(limbs: &[u64]) -> bool {
    limbs.iter().all(|limb| *limb < GOLDILOCKS_MODULUS)
}

fn append_length(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend((value.len() as u64).to_be_bytes());
    bytes.extend(value);
}

fn canonical_hex(value: &str, width: Option<usize>) -> anyhow::Result<Vec<u8>> {
    let decoded = hex::decode(value)?;
    anyhow::ensure!(!decoded.is_empty() && hex::encode(&decoded) == value, "noncanonical identity hex");
    if let Some(width) = width { anyhow::ensure!(decoded.len() == width, "identity hex width mismatch"); }
    Ok(decoded)
}

fn circuit_bytes(common: &CommonCircuitData<F, D>, verifier: &VerifierOnlyCircuitData<C, D>) -> anyhow::Result<(String, String)> {
    let common = hex::encode(common.to_bytes(&PsyGateSerializer).map_err(|error| anyhow::anyhow!("common serialization: {error:?}"))?);
    let verifier = hex::encode(verifier.to_bytes().map_err(|error| anyhow::anyhow!("verifier serialization: {error:?}"))?);
    Ok((common, verifier))
}

fn wrapper_fingerprint(verifier: &VerifierOnlyCircuitData<BN, D>) -> [u64; 4] {
    let mut fields = Vec::new();
    for hash in &verifier.constants_sigmas_cap.0 { fields.extend(hash.to_vec()); }
    fields.extend(verifier.circuit_digest.to_vec());
    let bytes = PoseidonBN254Hash::hash_no_pad(&fields).to_bytes();
    std::array::from_fn(|index| u64::from_be_bytes(bytes[index * 8..index * 8 + 8].try_into().expect("bn254 hash is 32 bytes")))
}

fn source_fingerprint(verifier: &VerifierOnlyCircuitData<C, D>) -> [u64; 4] {
    get_circuit_fingerprint_generic::<D, F, C>(verifier).elements.map(|field| F::to_canonical_u64(&field))
}

/// Configured chain index, bootstrap checkpoint identifier, and bootstrap root.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BridgeOpeningChain {
    pub chain_index: u8,
    pub bootstrap_id: u64,
    pub bootstrap_root: [u64; 4],
}

/// Token projection compiled into the opening identity and exported verifier.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BridgeOpeningTokenPolicy {
    pub chain_index: u8,
    pub contract_id: u32,
    pub token: String,
    pub full_leaf_hash: String,
    pub map_base: u32,
    pub capacity: u32,
    pub height: u8,
}

impl BridgeOpeningTokenPolicy {
    fn from_policy(policy: &BridgeTokenPolicy) -> anyhow::Result<Self> {
        anyhow::ensure!(policy.token_contract_id < 1 << 24 && policy.capacity > 0, "token policy exceeds its installed bounds");
        anyhow::ensure!(u64::from(policy.map_base) + u64::from(policy.capacity) < 1 << 32, "token map exceeds its address space");
        let height = policy.approved_leaf.state_tree_height.to_canonical_u64();
        anyhow::ensure!(height == 32, "approved contract leaf height is not 32");
        let mut token = [0u8; 20];
        for (index, limb) in policy.token_address.iter().enumerate() {
            anyhow::ensure!(index >= 3 || *limb == 0, "token address exceeds 160 bits");
            if index >= 3 { token[(index - 3) * 4..(index - 2) * 4].copy_from_slice(&limb.to_be_bytes()); }
        }
        let mut preimage = vec![F::from_canonical_u64(CONTRACT_LEAF_DOMAIN)];
        preimage.extend(policy.approved_leaf.to_qfelts());
        anyhow::ensure!(preimage.len() == 17, "approved contract leaf preimage width mismatch");
        let hash = PoseidonHash::hash_no_pad(&preimage);
        Ok(Self {
            chain_index: policy.chain_index, contract_id: policy.token_contract_id, token: hex::encode(token),
            full_leaf_hash: hex::encode(hash.to_bytes()), map_base: policy.map_base, capacity: policy.capacity, height: u8::try_from(height)?,
        })
    }
}

/// Setup binding for one installed version-4 opening graph.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BridgeOpeningIdentity {
    pub schema: u32,
    pub mode: String,
    pub version: u32,
    pub deposit_capacity: u32,
    pub withdrawal_capacity: u32,
    pub reward_capacity: u32,
    pub chain_count: u32,
    pub raw_pi_width: u32,
    pub node_source: String,
    pub native_source: String,
    pub plonky2_source: String,
    pub wrapper_source: String,
    pub config_hash: String,
    pub chains: Vec<BridgeOpeningChain>,
    pub token_policies: Vec<BridgeOpeningTokenPolicy>,
    pub source_fingerprint: [u64; 4],
    pub wrapper_fingerprint: [u64; 4],
    pub child_fingerprint: [u64; 4],
    pub top_fingerprint: [u64; 4],
    pub source_common: String,
    pub source_verifier: String,
    pub child_common_json: String,
    pub child_verifier_json: String,
    pub top_common_json: String,
    pub top_verifier_json: String,
    pub wrapper_common_json: String,
    pub wrapper_verifier_json: String,
}

impl BridgeOpeningIdentity {
    pub fn identity_hash(&self) -> anyhow::Result<String> {
        let width = bridge_aggregate_pi_len(self.chains.len());
        anyhow::ensure!(self.schema == 1 && self.mode == "BridgeOpening" && self.version == 4, "invalid bridge opening identity");
        anyhow::ensure!(self.deposit_capacity == DEPOSIT_CAPACITY && self.withdrawal_capacity == WITHDRAWAL_CAPACITY && self.reward_capacity == REWARD_CAPACITY, "bridge opening capacity mismatch");
        anyhow::ensure!((1..=8).contains(&self.chain_count) && self.chain_count as usize == self.chains.len() && self.raw_pi_width as usize == width, "bridge opening width mismatch");
        DigestBitsSources { node_source: self.node_source.clone(), native_source: self.native_source.clone(), plonky2_source: self.plonky2_source.clone(), wrapper_source: self.wrapper_source.clone() }.validate()?;
        for limbs in [&self.source_fingerprint, &self.wrapper_fingerprint, &self.child_fingerprint, &self.top_fingerprint] {
            anyhow::ensure!(canonical_limbs(limbs), "noncanonical fingerprint");
        }
        anyhow::ensure!(self.chains.windows(2).all(|pair| pair[0].chain_index < pair[1].chain_index), "bridge opening chains are not strictly ordered");
        anyhow::ensure!(self.chains.iter().all(|chain| canonical_limbs(&chain.bootstrap_root)), "noncanonical bridge bootstrap root");
        let mut seen = std::collections::BTreeSet::new();
        for policy in &self.token_policies {
            anyhow::ensure!(self.chains.iter().any(|chain| chain.chain_index == policy.chain_index), "token policy chain is not configured");
            anyhow::ensure!(policy.contract_id < 1 << 24 && policy.capacity > 0 && policy.height == 32, "invalid bridge opening token policy");
            anyhow::ensure!(u64::from(policy.map_base) + u64::from(policy.capacity) < 1 << 32, "token map exceeds its address space");
            anyhow::ensure!(seen.insert((policy.chain_index, policy.contract_id)), "duplicate bridge opening token policy");
            canonical_hex(&policy.token, Some(20))?;
            canonical_hex(&policy.full_leaf_hash, Some(32))?;
        }
        let config_hash = canonical_hex(&self.config_hash, Some(32))?;
        let source_common = canonical_hex(&self.source_common, None)?;
        let source_verifier = canonical_hex(&self.source_verifier, None)?;
        for value in [&self.child_common_json, &self.child_verifier_json, &self.top_common_json, &self.top_verifier_json, &self.wrapper_common_json, &self.wrapper_verifier_json] {
            serde_json::from_str::<serde_json::Value>(value)?;
        }
        let mut bytes = b"PsyBridge/BridgeOpening/4".to_vec();
        for value in [self.schema, self.version, self.deposit_capacity, self.withdrawal_capacity, self.reward_capacity, self.chain_count, self.raw_pi_width] {
            bytes.extend(value.to_be_bytes());
        }
        for value in [&self.mode, &self.node_source, &self.native_source, &self.plonky2_source, &self.wrapper_source] { append_length(&mut bytes, value.as_bytes()); }
        for limbs in [self.source_fingerprint, self.wrapper_fingerprint, self.child_fingerprint, self.top_fingerprint] {
            for limb in limbs { bytes.extend(limb.to_be_bytes()); }
        }
        for value in [source_common, source_verifier, self.child_common_json.as_bytes().to_vec(), self.child_verifier_json.as_bytes().to_vec(), self.top_common_json.as_bytes().to_vec(), self.top_verifier_json.as_bytes().to_vec(), self.wrapper_common_json.as_bytes().to_vec(), self.wrapper_verifier_json.as_bytes().to_vec()] {
            append_length(&mut bytes, &value);
        }
        bytes.extend(config_hash);
        for chain in &self.chains {
            bytes.push(chain.chain_index);
            bytes.extend(chain.bootstrap_id.to_be_bytes());
            for limb in chain.bootstrap_root { bytes.extend(limb.to_be_bytes()); }
        }
        for policy in &self.token_policies {
            bytes.push(policy.chain_index);
            bytes.extend(policy.contract_id.to_be_bytes());
            bytes.extend(canonical_hex(&policy.token, Some(20))?);
            bytes.extend(canonical_hex(&policy.full_leaf_hash, Some(32))?);
            bytes.extend(policy.map_base.to_be_bytes());
            bytes.extend(policy.capacity.to_be_bytes());
            bytes.push(policy.height);
        }
        Ok(hex::encode(CoreSha256Hasher::hash_bytes(&bytes).0))
    }

    /// Confirms that declared source bytes are the bytes of the supplied verifier.
    pub fn matches_source(&self, common: &CommonCircuitData<F, D>, verifier: &VerifierOnlyCircuitData<C, D>) -> anyhow::Result<bool> {
        let (common, verifier_bytes) = circuit_bytes(common, verifier)?;
        Ok(self.source_common == common && self.source_verifier == verifier_bytes && self.source_fingerprint == source_fingerprint(verifier))
    }

    /// Appends this identity's withdrawal-policy getter without changing the generic verifier.
    pub fn render_verifier(&self, generic_verifier: &str) -> anyhow::Result<String> {
        self.identity_hash()?;
        anyhow::ensure!(!generic_verifier.is_empty() && !generic_verifier.starts_with("error:"), "generic verifier export failed");
        anyhow::ensure!(generic_verifier.contains("contract Verifier"), "generic verifier has no Verifier contract");
        let product = self.product_verifier_contract()?;
        let generic = generic_verifier.trim_end_matches(['\n', '\r']);
        if let Some(base) = generic.strip_suffix(product.trim_end_matches('\n')) {
            anyhow::ensure!(!base.contains("function withdrawalTokenPolicyHash"), "generic verifier already defines withdrawalTokenPolicyHash");
            return Ok(generic_verifier.to_string());
        }
        anyhow::ensure!(!generic_verifier.contains("function withdrawalTokenPolicyHash") && !generic_verifier.contains("contract BridgeOpeningProductVerifier"), "generic verifier already contains product policy metadata");
        Ok(format!("{generic}\n{product}"))
    }

    fn product_verifier_contract(&self) -> anyhow::Result<String> {
        let mut contract = String::from("contract BridgeOpeningProductVerifier is Verifier {\n    function withdrawalTokenPolicyHash(uint8 chainIndex, uint32 contractId) external pure returns (bytes32) {\n");
        for policy in &self.token_policies {
            let token = canonical_hex(&policy.token, Some(20))?;
            let leaf = canonical_hex(&policy.full_leaf_hash, Some(32))?;
            let hash = policy_hash(policy.chain_index, policy.contract_id, &token, &leaf, policy.map_base, policy.capacity, policy.height);
            contract.push_str(&format!("        if (chainIndex == {} && contractId == {}) return {};\n", policy.chain_index, policy.contract_id, hash));
        }
        contract.push_str("        revert();\n    }\n}\n");
        Ok(contract)
    }
}

/// Cross-config conversion of one pinned `BridgeAggregateCircuit` proof.
pub struct BridgeOpeningWrapper {
    proof: ProofWithPublicInputsTarget<D>,
    circuit_data: CircuitData<F, BN, D>,
    identity: BridgeOpeningIdentity,
}

impl BridgeOpeningWrapper {
    pub fn build(
        source_common: &CommonCircuitData<F, D>, source_verifier: &VerifierOnlyCircuitData<C, D>,
        claim_common: &CommonCircuitData<F, D>, claim_verifier: &VerifierOnlyCircuitData<C, D>,
        sources: DigestBitsSources, config_hash: [u8; 32], chains: &[BridgeOpeningChain], policies: &[BridgeTokenPolicy],
    ) -> anyhow::Result<Self> {
        sources.validate()?;
        let chain_count = chains.len();
        let width = bridge_aggregate_pi_len(chain_count);
        anyhow::ensure!((1..=8).contains(&chain_count) && chains.windows(2).all(|pair| pair[0].chain_index < pair[1].chain_index), "invalid bridge opening chain list");
        anyhow::ensure!(source_common.num_public_inputs == width, "bridge aggregate public input width mismatch");
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let proof = builder.add_virtual_proof_with_pis(source_common);
        let verifier = builder.constant_verifier_data(source_verifier);
        builder.verify_proof::<C>(&proof, &verifier, source_common);
        for (target, value) in proof.public_inputs[..4].iter().zip(OPENING_PREFIX) {
            let prefix = builder.constant(F::from_canonical_u64(value));
            builder.connect(*target, prefix);
        }
        builder.register_public_inputs(&proof.public_inputs);
        let circuit_data = builder.build::<BN>();
        anyhow::ensure!(circuit_data.common.num_public_inputs == width, "bridge opening pass-through width mismatch");
        let (source_common_bytes, source_verifier_bytes) = circuit_bytes(source_common, source_verifier)?;
        let identity = BridgeOpeningIdentity {
            schema: 1, mode: "BridgeOpening".into(), version: 4, deposit_capacity: DEPOSIT_CAPACITY,
            withdrawal_capacity: WITHDRAWAL_CAPACITY, reward_capacity: REWARD_CAPACITY, chain_count: chain_count as u32, raw_pi_width: width as u32,
            node_source: sources.node_source, native_source: sources.native_source, plonky2_source: sources.plonky2_source, wrapper_source: sources.wrapper_source,
            config_hash: hex::encode(config_hash), chains: chains.to_vec(),
            token_policies: policies.iter().map(BridgeOpeningTokenPolicy::from_policy).collect::<anyhow::Result<_>>()?,
            source_fingerprint: source_fingerprint(source_verifier), wrapper_fingerprint: wrapper_fingerprint(&circuit_data.verifier_only),
            child_fingerprint: source_fingerprint(claim_verifier), top_fingerprint: source_fingerprint(source_verifier),
            source_common: source_common_bytes, source_verifier: source_verifier_bytes,
            child_common_json: json(claim_common)?, child_verifier_json: json(claim_verifier)?,
            top_common_json: json(source_common)?, top_verifier_json: json(source_verifier)?,
            wrapper_common_json: json(&circuit_data.common)?, wrapper_verifier_json: json(&circuit_data.verifier_only)?,
        };
        identity.identity_hash()?;
        Ok(Self { proof, circuit_data, identity })
    }

    pub fn identity(&self) -> &BridgeOpeningIdentity { &self.identity }

    pub fn prove(&self, source_proof: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<ProofWithPublicInputs<F, BN, D>> {
        anyhow::ensure!(source_proof.public_inputs.len() == self.circuit_data.common.num_public_inputs, "bridge source proof width mismatch");
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(&self.proof, source_proof)?;
        let proved = self.circuit_data.prove(witness)?;
        anyhow::ensure!(proved.public_inputs == source_proof.public_inputs, "bridge opening raw public inputs changed");
        self.circuit_data.verify(proved.clone())?;
        Ok(proved)
    }

    pub fn prove_groth16(&self, source_proof: &ProofWithPublicInputs<F, C, D>, artifact_dir: &str) -> anyhow::Result<UncompressedGroth16ProofData> {
        let converted = self.prove(source_proof)?;
        let (proof_json, verifier_json) = gnark_plonky2_verifier_ffi::generate_groth16_proof(&json(&self.circuit_data.common)?, &json(&converted)?, &json(&self.circuit_data.verifier_only)?, artifact_dir);
        anyhow::ensure!(!proof_json.starts_with("error:") && !verifier_json.starts_with("error:"), "generate_groth16_proof failed: {proof_json}{verifier_json}");
        let decoded: UncompressedGroth16ProofData = serde_json::from_str(&proof_json)?;
        check_returned_public_inputs(&decoded.public_inputs, &source_proof.public_inputs)?;
        Ok(decoded)
    }
}

fn check_returned_public_inputs(returned: &[String], source: &[F]) -> anyhow::Result<()> {
    anyhow::ensure!(returned.len() == source.len(), "bridge opening public input count mismatch");
    for (returned, source) in returned.iter().zip(source) {
        anyhow::ensure!(decode_goldilocks_word(returned)? == source.to_canonical_u64(), "bridge opening public input mismatch");
    }
    Ok(())
}

fn decode_goldilocks_word(word: &str) -> anyhow::Result<u64> {
    anyhow::ensure!(word.len() == 64 && word.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "public input must be 64 lowercase hexadecimal digits");
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(word, &mut bytes)?;
    anyhow::ensure!(bytes[..24] == [0; 24], "public input exceeds Goldilocks");
    let value = u64::from_be_bytes(bytes[24..].try_into()?);
    anyhow::ensure!(value < GOLDILOCKS_MODULUS, "public input is outside Goldilocks");
    Ok(value)
}

fn policy_hash(chain_index: u8, contract_id: u32, token: &[u8], full_leaf_hash: &[u8], map_base: u32, capacity: u32, height: u8) -> String {
    assert!(token.len() == 20 && full_leaf_hash.len() == 32, "policy hash ABI word width");
    let mut encoded = Vec::with_capacity(7 * 32);
    encoded.extend([0u8; 31]);
    encoded.push(chain_index);
    encoded.extend([0u8; 28]);
    encoded.extend(contract_id.to_be_bytes());
    encoded.extend([0u8; 12]);
    encoded.extend(token);
    encoded.extend(full_leaf_hash);
    encoded.extend([0u8; 28]);
    encoded.extend(map_base.to_be_bytes());
    encoded.extend([0u8; 28]);
    encoded.extend(capacity.to_be_bytes());
    encoded.extend([0u8; 31]);
    encoded.push(height);
    debug_assert_eq!(encoded.len(), 7 * 32);
    let mut keccak = tiny_keccak::Keccak::v256();
    tiny_keccak::Hasher::update(&mut keccak, &encoded);
    let mut digest = [0u8; 32];
    tiny_keccak::Hasher::finalize(keccak, &mut digest);
    format!("0x{}", hex::encode(digest))
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug, Eq, Hash, PartialOrd, Ord)]
pub struct Serialized2DFeltBN254(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 32]);
impl Default for Serialized2DFeltBN254 {
    fn default() -> Self { Self([0u8; 32]) }
}

impl Serialized2DFeltBN254 {
    pub fn from_hex_string(s: &str) -> Result<Self, FromHexError> {
        let bytes = hex::decode(s)?;
        assert_eq!(bytes.len(), 32);
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
    pub fn to_hex_string(&self) -> String { hex::encode(self.0) }
    pub fn rand() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }
    pub fn is_zero(&self) -> bool { self.0.iter().all(|&x| x == 0) }
    pub fn from_slice(data: &[u8]) -> Self {
        let mut array = [0u8; 32];
        array.copy_from_slice(data);
        Self(array)
    }
}

impl Display for Serialized2DFeltBN254 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", hex::encode(self.0)) }
}
impl TryFrom<&str> for Serialized2DFeltBN254 {
    type Error = FromHexError;
    fn try_from(value: &str) -> Result<Self, Self::Error> { Self::from_hex_string(value) }
}
impl TryFrom<String> for Serialized2DFeltBN254 {
    type Error = FromHexError;
    fn try_from(value: String) -> Result<Self, Self::Error> { Self::from_hex_string(&value) }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Hash, Ord, PartialOrd, Eq)]
pub struct UncompressedGroth16ProofData {
    pub pi_a: [String; 2],
    pub pi_b: [[String; 2]; 2],
    pub pi_c: [String; 2],
    pub public_inputs: Vec<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Hash, Ord, PartialOrd, Eq)]
pub struct ClaimPublicationProof {
    pub pi_a: [String; 2],
    pub pi_b: [[String; 2]; 2],
    pub pi_c: [String; 2],
    pub public_inputs: [String; 6],
}

type C = PoseidonGoldilocksConfig;
type BN = gnark_plonky2_wrapper::plonky2_config::PoseidonBN254GoldilocksConfig;
const D: usize = 2;
type F = GoldilocksField;

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};

    fn sources() -> DigestBitsSources {
        DigestBitsSources { node_source: "1".repeat(40), native_source: "2".repeat(40), plonky2_source: "3".repeat(40), wrapper_source: "4".repeat(40) }
    }
    fn chain(index: u8) -> BridgeOpeningChain {
        BridgeOpeningChain { chain_index: index, bootstrap_id: u64::from(index), bootstrap_root: [1, 2, 3, 4] }
    }
    fn policy(chain_index: u8, contract_id: u32) -> BridgeTokenPolicy {
        BridgeTokenPolicy {
            chain_index, token_contract_id: contract_id, token_address: [0, 0, 0, 0x01020304, 5, 6, 7, 8],
            approved_leaf: PsyContractLeaf { deployer: F::from_canonical_u64(9), state_tree_height: F::from_canonical_u64(32), ..PsyContractLeaf::default() },
            map_base: 8, capacity: 4,
        }
    }
    fn source(chains: usize) -> CircuitData<F, C, D> {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let inputs = builder.add_virtual_targets(bridge_aggregate_pi_len(chains));
        builder.register_public_inputs(&inputs);
        builder.build()
    }

    #[test]
    fn opening_forwards_exact_width_and_rejects_wrong_source() {
        for chains in [1usize, 8] {
            let source_circuit = source(chains);
            let child = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config()).build::<C>();
            let policies = [policy(1, 7)];
            let chain_list = (1..=chains as u8).map(chain).collect::<Vec<_>>();
            let wrapper = BridgeOpeningWrapper::build(&source_circuit.common, &source_circuit.verifier_only, &child.common, &child.verifier_only, sources(), [0x11; 32], &chain_list, &policies).unwrap();
            assert!(wrapper.identity().matches_source(&source_circuit.common, &source_circuit.verifier_only).unwrap());
            assert!(!wrapper.identity().matches_source(&child.common, &child.verifier_only).unwrap());
            assert_eq!(wrapper.circuit_data.common.num_public_inputs, bridge_aggregate_pi_len(chains));
            assert_eq!(bridge_aggregate_pi_len(8), 9340);
            let mut values = vec![0u64; bridge_aggregate_pi_len(chains)];
            values[..4].copy_from_slice(&OPENING_PREFIX);
            values[11] = 0x01020304;
            let prove = |values: &[u64], data: &CircuitData<F, C, D>| {
                let mut witness = PartialWitness::new();
                for (target, value) in data.prover_only.public_inputs.iter().zip(values) { witness.set_target(*target, F::from_canonical_u64(*value)).unwrap(); }
                data.prove(witness).unwrap()
            };
            let proof = prove(&values, &source_circuit);
            let converted = wrapper.prove(&proof).unwrap();
            assert_eq!(converted.public_inputs, proof.public_inputs);
            wrapper.circuit_data.verify(converted).unwrap();
            values[0] += 1;
            assert!(wrapper.prove(&prove(&values, &source_circuit)).is_err());
            let mut wrong_verifier = source_circuit.verifier_only.clone();
            wrong_verifier.circuit_digest.elements[0] += F::ONE;
            let wrong = BridgeOpeningWrapper::build(&source_circuit.common, &wrong_verifier, &child.common, &child.verifier_only, sources(), [0x11; 32], &chain_list, &policies).unwrap();
            let mut accepted = values.clone();
            accepted[0] -= 1;
            assert!(wrong.prove(&prove(&accepted, &source_circuit)).is_err());
        }
    }

    #[test]
    fn opening_identity_rejects_noncanonical_policy_and_width() {
        let source = source(1);
        let wrapper = BridgeOpeningWrapper::build(&source.common, &source.verifier_only, &source.common, &source.verifier_only, sources(), [0x22; 32], &[chain(1)], &[policy(1, 7)]).unwrap();
        let mut identity = wrapper.identity().clone();
        let original = identity.identity_hash().unwrap();
        identity.config_hash = hex::encode([0x33; 32]);
        assert_ne!(identity.identity_hash().unwrap(), original);
        identity.config_hash = hex::encode([0x22; 32]);
        identity.token_policies[0].full_leaf_hash = hex::encode([0x44; 32]);
        assert_ne!(identity.identity_hash().unwrap(), original);
        identity.token_policies[0].token = hex::encode([0u8; 21]);
        assert!(identity.identity_hash().is_err());
        identity.token_policies[0].token = wrapper.identity().token_policies[0].token.clone();
        identity.token_policies[0].height = 31;
        assert!(identity.identity_hash().is_err());
        identity.token_policies[0].height = 32;
        identity.raw_pi_width -= 1;
        assert!(identity.identity_hash().is_err());
        identity.raw_pi_width += 1;
        identity.chains[0].bootstrap_root[0] = GOLDILOCKS_MODULUS;
        assert!(identity.identity_hash().is_err());
        identity.mode = "DepositOpening".into();
        assert!(identity.identity_hash().is_err());
        let mut unknown = serde_json::to_value(wrapper.identity()).unwrap();
        unknown["reward_cutover"] = serde_json::json!(1);
        assert!(serde_json::from_value::<BridgeOpeningIdentity>(unknown).is_err());
    }

    #[test]
    fn returned_vector_rejects_count_order_and_noncanonical_scalars() {
        let word = |value: u64| format!("{value:064x}");
        let source = [4u64, 12, 0, GOLDILOCKS_MODULUS - 1].map(F::from_canonical_u64);
        let words = source.iter().map(|value| word(value.to_canonical_u64())).collect::<Vec<_>>();
        check_returned_public_inputs(&words, &source).unwrap();
        let mut swapped = words.clone();
        swapped.swap(0, 3);
        assert!(check_returned_public_inputs(&swapped, &source).is_err());
        assert!(check_returned_public_inputs(&words[..3], &source).is_err());
        assert!(check_returned_public_inputs(&[words.clone(), vec![word(0)]].concat(), &source).is_err());
        for invalid in [
            format!("0x{}", words[0]), words[0].to_uppercase(), "0".repeat(63), "0".repeat(65),
            format!("{}g", "0".repeat(63)), format!("{:064x}", u128::from(GOLDILOCKS_MODULUS)),
            format!("01{}", "0".repeat(62)), format!("{:064x}", u128::from(u64::MAX)),
        ] {
            let mut rejected = words.clone();
            rejected[3] = invalid;
            assert!(check_returned_public_inputs(&rejected, &source).is_err());
        }
    }

    #[test]
    fn product_verifier_appends_exact_policy_getter_without_changing_base() {
        let source = source(2);
        let wrapper = BridgeOpeningWrapper::build(&source.common, &source.verifier_only, &source.common, &source.verifier_only, sources(), [0x22; 32], &[chain(1), chain(2)], &[policy(1, 7), policy(2, 9)]).unwrap();
        let identity = wrapper.identity();
        let generic = "contract Verifier {\n    function verifyProof(uint256[8] calldata proof, uint256[] calldata input) public view {\n        success := staticcall(gas(), PRECOMPILE_VERIFY, f, 0x300, f, 0x20);\n    }\n}\n";
        let rendered = identity.render_verifier(generic).unwrap();
        assert!(rendered.starts_with(generic.trim_end()));
        assert!(rendered.contains("contract BridgeOpeningProductVerifier is Verifier"));
        assert!(rendered.contains("function withdrawalTokenPolicyHash(uint8 chainIndex, uint32 contractId) external pure returns (bytes32)"));
        let first = policy_hash(1, 7, &hex::decode(&identity.token_policies[0].token).unwrap(), &hex::decode(&identity.token_policies[0].full_leaf_hash).unwrap(), 8, 4, 32);
        let second = policy_hash(2, 9, &hex::decode(&identity.token_policies[1].token).unwrap(), &hex::decode(&identity.token_policies[1].full_leaf_hash).unwrap(), 8, 4, 32);
        assert!(rendered.contains(&format!("if (chainIndex == 1 && contractId == 7) return {first};")));
        assert!(rendered.contains(&format!("if (chainIndex == 2 && contractId == 9) return {second};")));
        assert!(rendered.contains("revert();"));
        assert_eq!(identity.render_verifier(&rendered).unwrap(), rendered);
        assert_eq!(identity.render_verifier(rendered.trim_end()).unwrap(), rendered);
        assert!(identity.render_verifier("").is_err());
        assert!(identity.render_verifier("error: missing key").is_err());
        assert!(identity.render_verifier("contract Other {}").is_err());
        assert!(identity.render_verifier(&format!("{generic}\nfunction withdrawalTokenPolicyHash(uint8,uint32)")).is_err());
        let mut changed = rendered.clone();
        changed.push_str("/*changed*/");
        let different = rendered.replacen("contractId == 7", "contractId == 8", 1);
        assert!(identity.render_verifier(&different).is_err());
        assert!(identity.render_verifier(&changed).is_err());
    }

    #[test]
    fn policy_hash_matches_abi_encode_of_seven_words() {
        let token = [0u8, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let leaf = [0x21u8; 32];
        let mut word = |high: usize, value: &[u8]| { let mut out = vec![0u8; 32 - value.len()]; out.extend(value); assert_eq!(out.len(), 32); assert!(out[..high].iter().all(|byte| *byte == 0)); out };
        let encoded = [word(31, &[3]), word(28, &7u32.to_be_bytes()), word(12, &token), leaf.to_vec(), word(28, &8u32.to_be_bytes()), word(28, &4u32.to_be_bytes()), word(31, &[32])].concat();
        assert_eq!(encoded.len(), 224);
        let mut keccak = tiny_keccak::Keccak::v256();
        tiny_keccak::Hasher::update(&mut keccak, &encoded);
        let mut digest = [0u8; 32];
        tiny_keccak::Hasher::finalize(keccak, &mut digest);
        assert_eq!(policy_hash(3, 7, &token, &leaf, 8, 4, 32), format!("0x{}", hex::encode(digest)));
    }

    #[test]
    fn claim_publication_words_reject_wrong_count() {
        let curve = ["0".repeat(64), "0".repeat(64)];
        let words = std::array::from_fn(|index| format!("{:064x}", index + 1));
        let proof = ClaimPublicationProof { pi_a: curve.clone(), pi_b: [curve.clone(), curve.clone()], pi_c: curve.clone(), public_inputs: words };
        let encoded = serde_json::to_string(&proof).unwrap();
        assert_eq!(serde_json::from_str::<ClaimPublicationProof>(&encoded).unwrap(), proof);
        for count in [0, 1, 2, 5, 7] {
            let wrong = serde_json::json!({"pi_a": [&curve[0], &curve[1]], "pi_b": [[&curve[0], &curve[1]], [&curve[0], &curve[1]]], "pi_c": [&curve[0], &curve[1]], "Commitments": "", "CommitmentPok": "0".repeat(128), "public_inputs": vec!["0".repeat(64); count]});
            assert!(serde_json::from_value::<ClaimPublicationProof>(wrong).is_err(), "accepted {count} aggregate words");
        }
    }
}

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
        let wrapped_circuit = WrappedCircuit::<DefaultParameters, gnark_plonky2_wrapper::parameters::Groth16WrapperParameters, D>::build(circuit);
        Self { wrapped_circuit, keystore_path }
    }

    pub fn prove_groth16(&self, inner_proof: &ProofWithPublicInputs<F, C, D>, save_wrapped_data_path: Option<&str>) -> anyhow::Result<UncompressedGroth16ProofData> {
        let wrapped_output = self.wrapped_circuit.prove(inner_proof)?;
        if let Some(path) = save_wrapped_data_path { wrapped_output.save(path)?; }
        let (proof_string, vk_string) = gnark_plonky2_verifier_ffi::generate_groth16_proof(&json(&wrapped_output.common_data)?, &json(&wrapped_output.proof)?, &json(&wrapped_output.verifier_data)?, &self.keystore_path);
        if proof_string.starts_with("error:") { anyhow::bail!("generate_groth16_proof failed: {}", proof_string); }
        if vk_string.starts_with("error:") { anyhow::bail!("generate_groth16_proof failed: {}", vk_string); }
        let decoded: UncompressedGroth16ProofData = serde_json::from_str(&proof_string)?;
        anyhow::ensure!(decoded.public_inputs.len() == wrapped_output.common_data.num_public_inputs, "groth16 public input width mismatch");
        Ok(decoded)
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
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let proof_target = builder.add_virtual_proof_with_pis(common_data);
        let verifier_data_target = builder.add_virtual_verifier_data(inner_verifier_data_cap_height);
        builder.verify_proof::<C>(&proof_target, &verifier_data_target, common_data);
        let expected_fingerprint = builder.constant_hash(fingerprint.into());
        let actual_fingerprint = builder.get_circuit_fingerprint::<<C as plonky2::plonk::config::GenericConfig<D>>::Hasher>(&verifier_data_target);
        builder.connect_hashes(expected_fingerprint, actual_fingerprint);
        builder.register_public_inputs(&proof_target.public_inputs);
        Self { proof_target, verifier_data_target, circuit_data: builder.build::<C>() }
    }

    pub fn into_shared_groth16_wrapper(self, keystore_path: String) -> SharedGroth16Wrapper { SharedGroth16Wrapper::new(self.circuit_data, keystore_path) }

    pub fn prove_groth16_with_shared_wrapper(&self, shared_wrapper: &SharedGroth16Wrapper, verifier_data: &VerifierOnlyCircuitData<C, D>, inner_proof: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<UncompressedGroth16ProofData> {
        anyhow::ensure!(inner_proof.public_inputs.len() == self.proof_target.public_inputs.len(), "deposit public input width mismatch");
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(&self.proof_target, inner_proof)?;
        witness.set_verifier_data_target(&self.verifier_data_target, verifier_data)?;
        let wrapper_proof = self.circuit_data.prove(witness)?;
        anyhow::ensure!(wrapper_proof.public_inputs == inner_proof.public_inputs, "deposit public inputs changed");
        let public_inputs_hash = QHashOut::from_4_felts_slice(&inner_proof.public_inputs[0..4]);
        shared_wrapper.prove_groth16(&wrapper_proof, Some(&format!("/tmp/plonky2_proof/{public_inputs_hash}")))
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
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let proof_target = builder.add_virtual_proof_with_pis(common_data);
        let verifier_data_target = builder.add_virtual_verifier_data(inner_verifier_data_cap_height);
        builder.verify_proof::<C>(&proof_target, &verifier_data_target, common_data);
        let expected_fingerprint = builder.constant_hash(fingerprint.into());
        let actual_fingerprint = builder.get_circuit_fingerprint::<<C as plonky2::plonk::config::GenericConfig<D>>::Hasher>(&verifier_data_target);
        builder.connect_hashes(expected_fingerprint, actual_fingerprint);
        builder.register_public_inputs(&proof_target.public_inputs);
        Self { proof_target, verifier_data_target, circuit_data: builder.build::<C>() }
    }

    pub fn into_shared_groth16_wrapper(self, keystore_path: String) -> SharedGroth16Wrapper { SharedGroth16Wrapper::new(self.circuit_data, keystore_path) }

    pub fn prove_groth16_with_shared_wrapper(&self, shared_wrapper: &SharedGroth16Wrapper, verifier_data: &VerifierOnlyCircuitData<C, D>, inner_proof: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<UncompressedGroth16ProofData> {
        anyhow::ensure!(inner_proof.public_inputs.len() == self.proof_target.public_inputs.len(), "withdrawal public input width mismatch");
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(&self.proof_target, inner_proof)?;
        witness.set_verifier_data_target(&self.verifier_data_target, verifier_data)?;
        let wrapper_proof = self.circuit_data.prove(witness)?;
        anyhow::ensure!(wrapper_proof.public_inputs == inner_proof.public_inputs, "withdrawal public inputs changed");
        let public_inputs_hash = QHashOut::from_4_felts_slice(&inner_proof.public_inputs[0..4]);
        shared_wrapper.prove_groth16(&wrapper_proof, Some(&format!("/tmp/plonky2_proof/{public_inputs_hash}")))
    }
}
