use std::{collections::BTreeSet, fmt, marker::PhantomData, path::{Component, Path, PathBuf}};

use alloy_primitives::U256;
use plonky2::{field::{goldilocks_field::GoldilocksField, types::PrimeField64}, hash::poseidon::PoseidonHash, plonk::config::Hasher};
use psy_client_common::{args::ContractCallData, data::qhashout::QHashOut};
use psy_client_data::{guta::end_cap_input::SubmitUserEndCapNonProofInput, qdata::contract::PsyContractLeaf};
use psy_crypto::{hash::core::sha256::CoreSha256Hasher, signature::secp256k1::core::PsyCompressedSecp256K1Signature};
use psy_prover::trace::{GeneratedTxTraceJson, TxTrace, TraceStep};
use psy_vm::ups::multisig::{MultisigAccount, MultisigSignatures};
use serde::{de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor}, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
pub const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
pub const BRIDGE_USER_ID: u64 = 524288;
pub type Hash4 = QHashOut<GoldilocksField>;
pub type Hex20 = Hex<20>;
pub type Hex32 = Hex<32>;
pub type Hex33 = Hex<33>;
pub type Hex64 = Hex<64>;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hex<const N: usize>(pub [u8; N]);
impl<const N: usize> fmt::Debug for Hex<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "0x{}", hex::encode(self.0)) }
}
impl<const N: usize> Serialize for Hex<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> { s.serialize_str(&format!("0x{}", hex::encode(self.0))) }
}
impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        let bytes = decode_hex(&text, N).map_err(de::Error::custom)?;
        if bytes.len() != N { return Err(de::Error::custom("invalid fixed hex width")); }
        let mut result = [0; N];
        result.copy_from_slice(&bytes);
        Ok(Self(result))
    }
}
fn decode_hex(text: &str, max_bytes: usize) -> Result<Vec<u8>, GuardianSignError> {
    let raw = text.strip_prefix("0x").ok_or(GuardianSignError::MalformedRequest)?;
    if raw.len() % 2 != 0 || raw.len() / 2 > max_bytes || !raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(GuardianSignError::MalformedRequest);
    }
    hex::decode(raw).map_err(|_| GuardianSignError::MalformedRequest)
}

// Keep original UTF-8: semantic trace equality must not change journal identity.
pub struct JsonText<T = Value> { text: String, marker: PhantomData<fn() -> T> }
impl<T> Clone for JsonText<T> {
    fn clone(&self) -> Self { Self { text: self.text.clone(), marker: PhantomData } }
}
impl<T> fmt::Debug for JsonText<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("JsonText(<retained>)") }
}
impl<T: Serialize + DeserializeOwned> JsonText<T> {
    pub fn parse(text: String) -> Result<Self, GuardianSignError> {
        parse_canonical_json::<T>(text.as_bytes())?;
        Ok(Self { text, marker: PhantomData })
    }
    pub fn decode(&self) -> Result<T, GuardianSignError> { parse_canonical_json(self.text.as_bytes()) }
    pub fn from_value(value: &T) -> Result<Self, GuardianSignError> {
        Self::parse(serde_json::to_string(value).map_err(|_| GuardianSignError::MalformedRequest)?)
    }
}
impl<T> JsonText<T> { pub fn as_str(&self) -> &str { &self.text } }
impl<T> Serialize for JsonText<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> { s.serialize_str(&self.text) }
}
impl<'de, T: Serialize + DeserializeOwned> Deserialize<'de> for JsonText<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(d)?).map_err(de::Error::custom)
    }
}

struct UniqueJson(Value);
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("JSON without duplicate keys") }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> { Ok(UniqueJson(Value::Bool(v))) }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> { Ok(UniqueJson(v.into())) }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> { Ok(UniqueJson(v.into())) }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v).map(|n| UniqueJson(Value::Number(n))).ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> { Ok(UniqueJson(Value::String(v.to_owned()))) }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> { Ok(UniqueJson(Value::String(v))) }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> { Ok(UniqueJson(Value::Null)) }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(v)) = a.next_element()? { values.push(v); }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = a.next_key::<String>()? {
                    if values.contains_key(&key) { return Err(de::Error::custom("duplicate key")); }
                    let UniqueJson(value) = a.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        d.deserialize_any(JsonVisitor)
    }
}
pub fn parse_canonical_json<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<T, GuardianSignError> {
    if bytes.len() > MAX_BODY_BYTES { return Err(GuardianSignError::MalformedRequest); }
    let UniqueJson(parsed) = serde_json::from_slice(bytes).map_err(|_| GuardianSignError::MalformedRequest)?;
    let typed: T = serde_json::from_value(parsed.clone()).map_err(|_| GuardianSignError::MalformedRequest)?;
    if serde_json::to_value(&typed).map_err(|_| GuardianSignError::MalformedRequest)? != parsed {
        return Err(GuardianSignError::MalformedRequest);
    }
    Ok(typed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardianSignError {
    MalformedRequest, UnauthorizedCaller, AccountIdentityConflict, AuthorizationMismatch,
    EvidenceUnavailable, EvidenceMismatch, StateMismatch, UnsupportedCall, PolicyMismatch,
    NonceConflict, WithdrawalNonceConflict, HistoryUnavailable, JournalUnavailable, KeyUnavailable, AccountHalted,
}
impl fmt::Display for GuardianSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for GuardianSignError {}
impl GuardianSignError {
    pub fn http_status(self) -> u16 {
        match self {
            Self::MalformedRequest => 400, Self::UnauthorizedCaller => 401,
            Self::AccountIdentityConflict | Self::UnsupportedCall | Self::PolicyMismatch | Self::EvidenceMismatch => 403,
            Self::AuthorizationMismatch | Self::StateMismatch | Self::NonceConflict | Self::WithdrawalNonceConflict => 409,
            Self::EvidenceUnavailable | Self::HistoryUnavailable | Self::JournalUnavailable | Self::KeyUnavailable | Self::AccountHalted => 503,
        }
    }
    pub fn retry_after_ms(self) -> u32 {
        match self { Self::EvidenceUnavailable | Self::HistoryUnavailable | Self::JournalUnavailable | Self::KeyUnavailable => 1000, _ => 0 }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianSignErrorResponse { pub request_id: Option<Hex32>, pub code: GuardianSignError, pub retry_after_ms: u32 }
impl GuardianSignErrorResponse {
    pub fn new(request_id: Option<Hex32>, code: GuardianSignError) -> Self { Self { request_id, code, retry_after_ms: code.retry_after_ms() } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedContract {
    pub contract_id: u32,
    pub contract_leaf_json: JsonText<PsyContractLeaf<GoldilocksField>>,
    pub compiler_artifact_json: JsonText<CompilerArtifact>,
    pub compiler_artifact_sha256: Hex32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerArtifact {
    pub state_tree_height: u16,
    pub circuit_definitions: Vec<psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition>,
    pub abi: Value,
}
impl ApprovedContract {
    pub fn compiler_artifact(&self) -> Result<CompilerArtifact, GuardianSignError> {
        if sha256(self.compiler_artifact_json.as_str().as_bytes()) != self.compiler_artifact_sha256 {
            return Err(GuardianSignError::AuthorizationMismatch);
        }
        let artifact = self.compiler_artifact_json.decode()?;
        if artifact.abi.get("schema_version").and_then(Value::as_str) != Some("2.0.0")
            || artifact.abi.get("contract").and_then(|c| c.get("state_tree_height")).and_then(Value::as_u64) != Some(u64::from(artifact.state_tree_height)) {
            return Err(GuardianSignError::AuthorizationMismatch);
        }
        Ok(artifact)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianAuthorization {
    pub version: u32, pub network_magic: u64, pub genesis_hash: Hex32, pub user_id: u64,
    pub account_json: JsonText<MultisigAccount>, pub account_public_key: Hash4, pub multisig_fingerprint: Hash4,
    pub deposit_contract_id: u32, pub withdrawal_contract_id: u32, pub fee_contract_id: u32,
    pub guta_fee: u64, pub da_fee: u64, pub max_fee: u64, pub max_endcap_proof_bytes: u32,
    pub approved_contracts: Vec<ApprovedContract>, pub chains: Vec<ChainAuthorization>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainAuthorization {
    pub chain_index: u8, pub chain_id: U256, pub genesis_hash: Hex32,
    pub bridge: Hex20, pub state_manager: Hex20, pub bridge_code_hash: Hex32,
    pub bridge_implementation: Hex20, pub bridge_implementation_code_hash: Hex32,
    pub state_manager_code_hash: Hex32, pub state_manager_implementation: Hex20,
    pub state_manager_implementation_code_hash: Hex32, pub deployment_block: u64,
    pub token_mappings: Vec<TokenMapping>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenMapping { pub token: Hex20, pub l2_contract_id: u32 }

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianRuntimeConfig {
    pub authorization_path: String, pub authorization_archive_path: String, pub authorization_index_path: String,
    pub rpc_config_path: String, pub listen_address: String, pub tls_certificate_path: String, pub tls_private_key_path: String,
    pub client_ca_path: String, pub allowed_client_certificate_sha256: Vec<Hex32>,
    pub db_path: String, pub signing_key_secret_path: String,
    pub signing_key_password_secret_path: String, pub signing_authorization_path: String,
    pub l2_rpc_url: String, pub l2_rpc_endpoint_pins: Vec<L2RpcEndpointPin>,
    pub l1_rpc_urls: Vec<ChainEndpoint>, pub history_urls: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainEndpoint { pub chain_index: u8, pub rpc_url: String }
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum L2RpcEndpointRole { Coordinator = 0, Realm = 1 }
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L2RpcEndpointPin {
    pub role: L2RpcEndpointRole, pub config_id: u64, pub rpc_url: String, pub tls_certificate_sha256: Option<Hex32>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningAuthorization {
    pub network_magic: u64, pub user_id: u64, pub public_key: Hex33,
    pub db_path: String, pub not_before_unix: u64, pub expires_at_unix: u64,
    pub exclusive_key_use: bool, pub complete_journal: bool, pub revoked: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianAuthorizationIndex { pub active_version: u32, pub versions: Vec<GuardianAuthorizationVersion> }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianAuthorizationVersion { pub version: u32, pub sha256: Hex32 }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum GuardianOperation { Bridge = 0, Bootstrap = 1, ReplacePolicy = 2 }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianSignRequest {
    pub schema_version: u32, pub authorization_version: u32, pub network_magic: u64,
    pub genesis_hash: Hex32, pub user_id: u64, pub session_nonce: u64, pub operation: GuardianOperation,
    pub trace_json: JsonText<GeneratedTxTraceJson>, pub deposit_anchors: Vec<DepositAnchor>,
    pub withdrawal_records: Vec<WithdrawalBurnRecord>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositAnchor { pub chain_index: u8, pub block_number: u64, pub block_hash: Hex32, pub old_count: u32, pub new_count: u32 }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithdrawalBurnRecord {
    pub sender_user_id: u32, pub token_contract_id: u32, pub destination_chain_index: u8,
    pub token: [u32; 8], pub amount: [u32; 8], pub recipient: [u32; 8], pub nonce: [u32; 8],
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianSignResponse {
    pub request_id: Hex32, pub network_magic: u64, pub user_id: u64, pub session_nonce: u64,
    pub policy_commitment: Hash4, pub member_index: u8, pub message: Hex32, pub public_key: Hex33, pub signature: Hex64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct GuardianSigned {
    pub network_magic: u64, pub user_id: u64, pub nonce: u64,
    pub request_bytes: Vec<u8>, pub authorization_bytes: Vec<u8>, pub starting_leaf_hash: Hash4,
    pub ending_leaf_hash: Hash4, pub message: [u8; 32],
    #[serde(with = "signed_signature")]
    pub signature: Option<[u8; 64]>,
}

mod signed_signature {
    use super::*;

    pub fn serialize<S: Serializer>(value: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error> {
        value.map(Hex).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error> {
        Option::<Hex64>::deserialize(deserializer).map(|value| value.map(|signature| signature.0))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianSessionRecord {
    pub request_json: JsonText<GuardianSignRequest>, pub signatures_json: JsonText<MultisigSignatures>,
    pub endcap_input_json: JsonText<SubmitUserEndCapNonProofInput<GoldilocksField>>,
    pub endcap_proof_hex: String, pub included_checkpoint_id: u64, pub included_checkpoint_hash: Hash4,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianSession {
    pub network_magic: u64, pub user_id: u64, pub nonce: u64, pub record: GuardianSessionRecord,
    pub starting_leaf_hash: Hash4, pub ending_leaf_hash: Hash4, pub withdrawal_appends: Vec<WithdrawalAppendRecord>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithdrawalAppendRecord { pub chain_index: u8, pub append_index: u32, pub burn: WithdrawalBurnRecord }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianSessionsResponse { pub sessions: Vec<GuardianSessionRecord>, pub next_after_nonce: u64, pub has_more: bool }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardianAccountState { Active, Halted }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HaltReason { FinalityConflict, CheckpointConflict, NonceConsumedDifferently, IncludedTransitionMissing, AppendHistoryMismatch, SigningAuthorizationInvalid }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianAccount {
    pub network_magic: u64, pub user_id: u64, pub state: GuardianAccountState,
    pub last_checkpoint_id: u64, pub last_checkpoint_hash: Hash4, pub imported_nonce: Option<u64>,
    pub authorization_version: u32, pub halt_reason: Option<HaltReason>,
}

fn canonical_field(value: u64) -> bool { value > 0 && value < GOLDILOCKS_MODULUS }
pub fn validate_hash(hash: Hash4) -> Result<(), GuardianSignError> {
    if hash.0.elements.iter().any(|v| v.0 >= GOLDILOCKS_MODULUS) { return Err(GuardianSignError::MalformedRequest); }
    Ok(())
}
pub fn encode_hash(hash: Hash4) -> Result<[u8; 32], GuardianSignError> { validate_hash(hash)?; Ok(hash.to_le_bytes()) }
fn put_text(bytes: &mut Vec<u8>, text: &str) { bytes.extend_from_slice(&(text.len() as u64).to_le_bytes()); bytes.extend_from_slice(text.as_bytes()); }
fn put_words(bytes: &mut Vec<u8>, words: &[u32; 8]) { for word in words { bytes.extend_from_slice(&word.to_le_bytes()); } }

impl WithdrawalBurnRecord {
    pub fn amount_u64(&self) -> Result<u64, GuardianSignError> {
        let amount = ((self.amount[6] as u64) << 32) | self.amount[7] as u64;
        if self.amount[..6] != [0; 6] || !canonical_field(amount) { return Err(GuardianSignError::EvidenceMismatch); }
        Ok(amount)
    }
    pub fn token_address(&self) -> Result<Hex20, GuardianSignError> { Self::address(&self.token) }
    pub fn recipient_address(&self) -> Result<Hex20, GuardianSignError> {
        let address = Self::address(&self.recipient)?;
        if address.0 == [0; 20] { return Err(GuardianSignError::EvidenceMismatch); }
        Ok(address)
    }
    fn address(words: &[u32; 8]) -> Result<Hex20, GuardianSignError> {
        if words[..3] != [0; 3] { return Err(GuardianSignError::EvidenceMismatch); }
        let mut address = [0; 20];
        for (part, word) in address.chunks_exact_mut(4).zip(&words[3..]) { part.copy_from_slice(&word.to_be_bytes()); }
        Ok(Hex(address))
    }
    pub fn selection_key(&self) -> (u8, u32, u32, [u32; 8]) { (self.destination_chain_index, self.sender_user_id, self.token_contract_id, self.nonce) }
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.sender_user_id.to_le_bytes()); bytes.extend_from_slice(&self.token_contract_id.to_le_bytes());
        bytes.push(self.destination_chain_index);
        for words in [&self.token, &self.amount, &self.recipient, &self.nonce] { put_words(bytes, words); }
    }
}
impl GuardianSignRequest {
    pub fn parse(bytes: &[u8]) -> Result<Self, GuardianSignError> { let request: Self = parse_canonical_json(bytes)?; request.validate()?; Ok(request) }
    pub fn validate(&self) -> Result<(), GuardianSignError> {
        if self.schema_version != 1 || self.authorization_version == 0 || !canonical_field(self.network_magic) || self.user_id != BRIDGE_USER_ID || !canonical_field(self.session_nonce)
            || self.deposit_anchors.len() > 256 || self.withdrawal_records.len() > 1024 { return Err(GuardianSignError::MalformedRequest); }
        if self.operation != GuardianOperation::Bridge && (!self.deposit_anchors.is_empty() || !self.withdrawal_records.is_empty()) { return Err(GuardianSignError::UnsupportedCall); }
        if self.operation == GuardianOperation::Bridge && self.deposit_anchors.is_empty() && self.withdrawal_records.is_empty() { return Err(GuardianSignError::UnsupportedCall); }
        if self.deposit_anchors.windows(2).any(|w| w[0].chain_index >= w[1].chain_index)
            || self.deposit_anchors.iter().any(|a| a.new_count <= a.old_count || a.block_hash.0 == [0; 32]) { return Err(GuardianSignError::EvidenceMismatch); }
        if self.withdrawal_records.windows(2).any(|w| w[0].selection_key() >= w[1].selection_key()) { return Err(GuardianSignError::EvidenceMismatch); }
        let mut identities = BTreeSet::new(); let mut nonces = BTreeSet::new();
        for record in &self.withdrawal_records {
            record.amount_u64()?; record.token_address()?; record.recipient_address()?;
            if !identities.insert((record.sender_user_id, record.token_contract_id, record.nonce)) || !nonces.insert((record.destination_chain_index, record.nonce)) { return Err(GuardianSignError::WithdrawalNonceConflict); }
        }
        self.decode_trace()?;
        Ok(())
    }
    pub fn decode_trace(&self) -> Result<TxTrace, GuardianSignError> {
        let envelope = self.trace_json.decode()?;
        if envelope.trace.encoding != "json" { return Err(GuardianSignError::MalformedRequest); }
        let trace: TxTrace = parse_canonical_json(envelope.trace.payload.as_bytes())?;
        let _: ContractCallData = parse_canonical_json(&serde_json::to_vec(&envelope.call_data).map_err(|_| GuardianSignError::MalformedRequest)?)?;
        if envelope.user_id != self.user_id.to_string() || trace.meta.user_id != self.user_id || trace.meta.network_magic != self.network_magic
            || envelope.pk_hash != trace.meta.public_key.to_string() || envelope.sig_hash != trace.finalization.sig_hash.to_string()
            || envelope.tx_hash != trace.finalization.tx_hash.to_string() || envelope.tx_count != trace.steps.len() as u64
            || trace.finalization.nonce.0 >= GOLDILOCKS_MODULUS || trace.finalization.nonce.to_canonical_u64() != self.session_nonce { return Err(GuardianSignError::StateMismatch); }
        if trace.ups_start_witness.proof.is_some() || trace.steps.iter().any(|step| match step {
            TraceStep::Standard(c) | TraceStep::BurnFee(c) | TraceStep::Inlined(c) | TraceStep::Deferred(c) => c.proof.is_some(),
            TraceStep::ExternalProof(_) => true, TraceStep::ZkSign(_) => false,
        }) { return Err(GuardianSignError::MalformedRequest); }
        Ok(trace)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GuardianSignError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(self.trace_json.as_str().len() + 128 + self.withdrawal_records.len() * 137);
        bytes.extend_from_slice(b"PSYGS001");
        bytes.extend_from_slice(&self.schema_version.to_le_bytes()); bytes.extend_from_slice(&self.authorization_version.to_le_bytes());
        bytes.extend_from_slice(&self.network_magic.to_le_bytes()); bytes.extend_from_slice(&self.genesis_hash.0);
        bytes.extend_from_slice(&self.user_id.to_le_bytes()); bytes.extend_from_slice(&self.session_nonce.to_le_bytes()); bytes.push(self.operation as u8);
        put_text(&mut bytes, self.trace_json.as_str());
        bytes.extend_from_slice(&(self.deposit_anchors.len() as u64).to_le_bytes());
        for a in &self.deposit_anchors { bytes.push(a.chain_index); bytes.extend_from_slice(&a.block_number.to_le_bytes()); bytes.extend_from_slice(&a.block_hash.0); bytes.extend_from_slice(&a.old_count.to_le_bytes()); bytes.extend_from_slice(&a.new_count.to_le_bytes()); }
        bytes.extend_from_slice(&(self.withdrawal_records.len() as u64).to_le_bytes());
        for record in &self.withdrawal_records { record.encode(&mut bytes); }
        if bytes.len() > MAX_BODY_BYTES { return Err(GuardianSignError::MalformedRequest); }
        Ok(bytes)
    }
    pub fn request_id(&self) -> Result<Hex32, GuardianSignError> { Ok(sha256(&self.canonical_bytes()?)) }
    pub fn validate_authorization(&self, authorization: &GuardianAuthorization) -> Result<(), GuardianSignError> {
        self.validate()?;
        if self.authorization_version != authorization.version || self.network_magic != authorization.network_magic || self.genesis_hash != authorization.genesis_hash || self.user_id != authorization.user_id { return Err(GuardianSignError::AuthorizationMismatch); }
        if self.decode_trace()?.meta.public_key != authorization.account_public_key { return Err(GuardianSignError::AccountIdentityConflict); }
        for anchor in &self.deposit_anchors { authorization.chain(anchor.chain_index)?; }
        for record in &self.withdrawal_records {
            let token = record.token_address()?;
            if !authorization.chain(record.destination_chain_index)?.token_mappings.iter().any(|m| m.token == token && m.l2_contract_id == record.token_contract_id) { return Err(GuardianSignError::EvidenceMismatch); }
        }
        Ok(())
    }
}
pub fn sha256(bytes: &[u8]) -> Hex32 { Hex(CoreSha256Hasher::hash_bytes(bytes).0) }
pub fn traces_equal(supplied: &TxTrace, replayed: &TxTrace) -> Result<bool, GuardianSignError> {
    Ok(serde_json::to_value(supplied).map_err(|_| GuardianSignError::MalformedRequest)? == serde_json::to_value(replayed).map_err(|_| GuardianSignError::MalformedRequest)?)
}

impl GuardianAuthorization {
    pub fn parse(bytes: &[u8]) -> Result<Self, GuardianSignError> { parse_canonical_json(bytes) }
    pub fn chain(&self, index: u8) -> Result<&ChainAuthorization, GuardianSignError> {
        self.chains.binary_search_by_key(&index, |c| c.chain_index).ok().map(|i| &self.chains[i]).ok_or(GuardianSignError::AuthorizationMismatch)
    }
    pub fn validate(&self, guta_fee: u64, da_fee: u64, max_endcap_proof_bytes: u32) -> Result<(), GuardianSignError> {
        let mismatch = GuardianSignError::AuthorizationMismatch;
        if self.version == 0 || !canonical_field(self.network_magic) || self.genesis_hash.0 == [0; 32] || self.user_id != BRIDGE_USER_ID
            || self.deposit_contract_id != 2 || self.withdrawal_contract_id != 3 || self.fee_contract_id != 0
            || self.guta_fee != guta_fee || self.da_fee != da_fee
            || self.max_endcap_proof_bytes == 0 || self.max_endcap_proof_bytes != max_endcap_proof_bytes
            || self.chains.is_empty() || self.chains.len() > 256 { return Err(mismatch); }
        validate_hash(self.account_public_key)?; validate_hash(self.multisig_fingerprint)?;
        let account = self.account_json.decode()?;
        if account.contract_id != 6 || account.initial_policy.threshold != 2 || account.initial_policy.member_count != 3 { return Err(GuardianSignError::PolicyMismatch); }
        for member in account.initial_policy.member_hashes { validate_hash(member)?; }
        let param = account.public_key_param().map_err(|_| GuardianSignError::PolicyMismatch)?;
        let key = QHashOut(PoseidonHash::two_to_one(self.multisig_fingerprint.0, param.0));
        if key != self.account_public_key || self.multisig_fingerprint == Hash4::ZERO { return Err(GuardianSignError::AccountIdentityConflict); }
        if self.approved_contracts.windows(2).any(|w| w[0].contract_id >= w[1].contract_id) || self.chains.windows(2).any(|w| w[0].chain_index >= w[1].chain_index) { return Err(mismatch); }
        let approved: BTreeSet<_> = self.approved_contracts.iter().map(|c| c.contract_id).collect();
        if [0, 2, 3, 6].iter().any(|id| !approved.contains(id)) { return Err(mismatch); }
        let mut chain_ids = BTreeSet::new();
        for chain in &self.chains {
            if chain.chain_id == U256::ZERO || !chain_ids.insert(chain.chain_id) || chain.genesis_hash.0 == [0; 32]
                || [chain.bridge, chain.state_manager, chain.bridge_implementation, chain.state_manager_implementation].iter().any(|a| a.0 == [0; 20])
                || [chain.bridge_code_hash, chain.bridge_implementation_code_hash, chain.state_manager_code_hash, chain.state_manager_implementation_code_hash].iter().any(|h| h.0 == [0; 32])
                || chain.token_mappings.is_empty() || chain.token_mappings.len() > 65536
                || chain.token_mappings.windows(2).any(|w| w[0].token >= w[1].token) { return Err(mismatch); }
            for mapping in &chain.token_mappings {
                if !approved.contains(&mapping.l2_contract_id) { return Err(mismatch); }
            }
        }
        for contract in &self.approved_contracts {
            contract.contract_leaf_json.decode()?;
            contract.compiler_artifact()?;
        }
        Ok(())
    }
}

impl GuardianAuthorizationIndex {
    pub fn parse(bytes: &[u8]) -> Result<Self, GuardianSignError> { let index: Self = parse_canonical_json(bytes)?; index.validate()?; Ok(index) }
    pub fn validate(&self) -> Result<(), GuardianSignError> {
        if self.active_version == 0 || self.versions.is_empty() || self.versions.iter().any(|v| v.version == 0)
            || self.versions.windows(2).any(|w| w[0].version >= w[1].version)
            || !self.versions.iter().any(|v| v.version == self.active_version) { return Err(GuardianSignError::AuthorizationMismatch); }
        Ok(())
    }
    pub fn version(&self, version: u32) -> Result<&GuardianAuthorizationVersion, GuardianSignError> {
        self.validate()?;
        self.versions.binary_search_by_key(&version, |v| v.version).ok().map(|i| &self.versions[i]).ok_or(GuardianSignError::HistoryUnavailable)
    }
    pub fn archive_file(&self, archive: &Path, version: u32) -> Result<PathBuf, GuardianSignError> {
        self.version(version)?;
        Ok(archive.join(format!("{version}.json")))
    }
    pub fn resolve(&self, version: u32, bytes: &[u8]) -> Result<GuardianAuthorization, GuardianSignError> {
        if sha256(bytes) != self.version(version)?.sha256 { return Err(GuardianSignError::AuthorizationMismatch); }
        let authorization = GuardianAuthorization::parse(bytes)?;
        if authorization.version != version { return Err(GuardianSignError::AuthorizationMismatch); }
        Ok(authorization)
    }
    pub fn validate_update(&self, next: &Self) -> Result<(), GuardianSignError> {
        self.validate()?; next.validate()?;
        for old in &self.versions {
            if next.version(old.version).map_err(|_| GuardianSignError::AuthorizationMismatch)?.sha256 != old.sha256 { return Err(GuardianSignError::AuthorizationMismatch); }
        }
        Ok(())
    }
}

fn relative_path(value: &str) -> bool {
    !value.is_empty() && Path::new(value).components().all(|c| matches!(c, Component::Normal(_)))
}
fn validate_endpoint(value: &str, origin_only: bool) -> Result<(), GuardianSignError> {
    let url = url::Url::parse(value).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(), Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) => host == "localhost", None => false,
    };
    if !(url.scheme() == "https" || (url.scheme() == "http" && loopback)) || url.host().is_none()
        || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some()
        || (origin_only && (url.path() != "/" || url.query().is_some())) { return Err(GuardianSignError::AuthorizationMismatch); }
    Ok(())
}
impl GuardianRuntimeConfig {
    pub fn validate(&self, authorization: &GuardianAuthorization, index: &GuardianAuthorizationIndex) -> Result<(), GuardianSignError> {
        index.validate()?;
        for path in [&self.authorization_path, &self.authorization_archive_path, &self.authorization_index_path, &self.tls_certificate_path,
            &self.tls_private_key_path, &self.client_ca_path, &self.db_path, &self.signing_key_secret_path,
            &self.rpc_config_path, &self.signing_key_password_secret_path, &self.signing_authorization_path] {
            if !relative_path(path) { return Err(GuardianSignError::AuthorizationMismatch); }
        }
        if Path::new(&self.authorization_path) != index.archive_file(Path::new(&self.authorization_archive_path), index.active_version)?
            || authorization.version != index.active_version || self.listen_address.parse::<std::net::SocketAddr>().is_err()
            || self.tls_private_key_path == self.signing_key_secret_path
            || !(1..=16).contains(&self.allowed_client_certificate_sha256.len())
            || self.allowed_client_certificate_sha256.iter().collect::<BTreeSet<_>>().len() != self.allowed_client_certificate_sha256.len()
            || !(1..=4).contains(&self.history_urls.len()) || self.l1_rpc_urls.len() != authorization.chains.len() { return Err(GuardianSignError::AuthorizationMismatch); }
        let mut routes = BTreeSet::new();
        for pin in &self.l2_rpc_endpoint_pins {
            let url = pin.validate()?;
            if !routes.insert((pin.role, pin.config_id, url.to_string())) { return Err(GuardianSignError::AuthorizationMismatch); }
        }
        if !self.l2_rpc_endpoint_pins.iter().any(|pin| pin.role == L2RpcEndpointRole::Coordinator && pin.rpc_url == self.l2_rpc_url) {
            return Err(GuardianSignError::AuthorizationMismatch);
        }
        let mut chains = BTreeSet::new();
        for endpoint in &self.l1_rpc_urls {
            authorization.chain(endpoint.chain_index)?;
            if !chains.insert(endpoint.chain_index) { return Err(GuardianSignError::AuthorizationMismatch); }
            validate_endpoint(&endpoint.rpc_url, false)?;
        }
        for endpoint in &self.history_urls { validate_endpoint(endpoint, true)?; }
        Ok(())
    }
}

impl GuardianSigned {
    pub fn validate(&self) -> Result<(), GuardianSignError> {
        if !canonical_field(self.network_magic) || self.user_id != BRIDGE_USER_ID || !canonical_field(self.nonce)
            || self.request_bytes.len() > MAX_BODY_BYTES || self.authorization_bytes.len() > MAX_BODY_BYTES { return Err(GuardianSignError::JournalUnavailable); }
        let request = GuardianSignRequest::from_canonical_bytes(&self.request_bytes).map_err(|_| GuardianSignError::JournalUnavailable)?;
        if request.network_magic != self.network_magic || request.user_id != self.user_id || request.session_nonce != self.nonce {
            return Err(GuardianSignError::JournalUnavailable);
        }
        validate_hash(self.starting_leaf_hash)?; validate_hash(self.ending_leaf_hash)?;
        Ok(())
    }
}
impl GuardianAccount {
    pub fn validate(&self) -> Result<(), GuardianSignError> {
        if !canonical_field(self.network_magic) || self.user_id != BRIDGE_USER_ID || self.authorization_version == 0
            || self.imported_nonce.is_some_and(|n| !canonical_field(n))
            || (self.state == GuardianAccountState::Halted) != self.halt_reason.is_some() { return Err(GuardianSignError::JournalUnavailable); }
        validate_hash(self.last_checkpoint_hash)
    }
}
impl GuardianSessionRecord {
    pub fn validate(&self, authorization: &GuardianAuthorization) -> Result<GuardianSignRequest, GuardianSignError> {
        let request = self.request_json.decode()?;
        request.validate_authorization(authorization)?;
        validate_hash(self.included_checkpoint_hash)?;
        let signatures = self.signatures_json.decode()?;
        if signatures.member_indices.len() != 2 || signatures.signatures.len() != 2
            || signatures.member_indices[0] >= signatures.member_indices[1] || signatures.member_indices[1] > 2 { return Err(GuardianSignError::PolicyMismatch); }
        if self.proof_bytes(authorization.max_endcap_proof_bytes)?.is_empty() { return Err(GuardianSignError::HistoryUnavailable); }
        self.endcap_input_json.decode()?;
        let page = GuardianSessionsResponse { sessions: vec![self.clone()], next_after_nonce: request.session_nonce, has_more: false };
        page.to_bytes()?;
        Ok(request)
    }
    pub fn proof_bytes(&self, max_endcap_proof_bytes: u32) -> Result<Vec<u8>, GuardianSignError> {
        decode_hex(&self.endcap_proof_hex, (max_endcap_proof_bytes as usize).min(MAX_BODY_BYTES))
    }
}
impl GuardianSessionsResponse {
    pub fn to_bytes(&self) -> Result<Vec<u8>, GuardianSignError> {
        let bytes = serde_json::to_vec(self).map_err(|_| GuardianSignError::MalformedRequest)?;
        if bytes.len() > MAX_BODY_BYTES { return Err(GuardianSignError::MalformedRequest); }
        Ok(bytes)
    }
    pub fn validate_page(&self, after_nonce: u64, limit: u8) -> Result<(), GuardianSignError> {
        if !(1..=64).contains(&limit) || self.sessions.len() > usize::from(limit) { return Err(GuardianSignError::MalformedRequest); }
        self.to_bytes()?;
        let mut nonce = after_nonce;
        for session in &self.sessions {
            let request = session.request_json.decode()?;
            if request.session_nonce <= nonce { return Err(GuardianSignError::HistoryUnavailable); }
            nonce = request.session_nonce;
        }
        if self.next_after_nonce != nonce { return Err(GuardianSignError::HistoryUnavailable); }
        Ok(())
    }
}

pub fn validate_future_endcap_proof_size(request: &JsonText<GuardianSignRequest>, endcap_input: &SubmitUserEndCapNonProofInput<GoldilocksField>, max_endcap_proof_bytes: u32) -> Result<(), GuardianSignError> {
    if max_endcap_proof_bytes == 0 || (max_endcap_proof_bytes as usize) > MAX_BODY_BYTES / 2 { return Err(GuardianSignError::MalformedRequest); }
    let signature = PsyCompressedSecp256K1Signature {
        public_key: [255; 33], signature: [255; 64], message: psy_client_common::data::base_types::hash256::Hash256([255; 32]),
    };
    let envelope = GuardianSessionRecord {
        request_json: request.clone(),
        signatures_json: JsonText::from_value(&MultisigSignatures { member_indices: vec![0, 2], signatures: vec![signature; 2] })?,
        endcap_input_json: JsonText::from_value(endcap_input)?, endcap_proof_hex: format!("0x{}", "ff".repeat(max_endcap_proof_bytes as usize)),
        included_checkpoint_id: u64::MAX, included_checkpoint_hash: QHashOut::from_values(GOLDILOCKS_MODULUS - 1, GOLDILOCKS_MODULUS - 1, GOLDILOCKS_MODULUS - 1, GOLDILOCKS_MODULUS - 1),
    };
    GuardianSessionsResponse { sessions: vec![envelope], next_after_nonce: u64::MAX, has_more: false }.to_bytes()?;
    Ok(())
}

struct RequestBytes<'a> { remaining: &'a [u8] }
impl<'a> RequestBytes<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], GuardianSignError> {
        if self.remaining.len() < N { return Err(GuardianSignError::MalformedRequest); }
        let (bytes, rest) = self.remaining.split_at(N); self.remaining = rest;
        bytes.try_into().map_err(|_| GuardianSignError::MalformedRequest)
    }
    fn u8(&mut self) -> Result<u8, GuardianSignError> { Ok(self.take::<1>()?[0]) }
    fn u32(&mut self) -> Result<u32, GuardianSignError> { Ok(u32::from_le_bytes(self.take()?)) }
    fn u64(&mut self) -> Result<u64, GuardianSignError> { Ok(u64::from_le_bytes(self.take()?)) }
    fn count(&mut self, max: usize) -> Result<usize, GuardianSignError> {
        let count = usize::try_from(self.u64()?).map_err(|_| GuardianSignError::MalformedRequest)?;
        if count > max { return Err(GuardianSignError::MalformedRequest); }
        Ok(count)
    }
    fn words(&mut self) -> Result<[u32; 8], GuardianSignError> {
        let mut words = [0; 8]; for word in &mut words { *word = self.u32()?; } Ok(words)
    }
}
impl GuardianSignRequest {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, GuardianSignError> {
        if bytes.len() > MAX_BODY_BYTES { return Err(GuardianSignError::MalformedRequest); }
        let mut input = RequestBytes { remaining: bytes };
        if input.take::<8>()? != *b"PSYGS001" { return Err(GuardianSignError::MalformedRequest); }
        let schema_version = input.u32()?; let authorization_version = input.u32()?;
        let network_magic = input.u64()?; let genesis_hash = Hex(input.take()?);
        let user_id = input.u64()?; let session_nonce = input.u64()?;
        let operation = match input.u8()? { 0 => GuardianOperation::Bridge, 1 => GuardianOperation::Bootstrap, 2 => GuardianOperation::ReplacePolicy, _ => return Err(GuardianSignError::MalformedRequest) };
        let length = input.count(input.remaining.len())?;
        if length > input.remaining.len() { return Err(GuardianSignError::MalformedRequest); }
        let (text, rest) = input.remaining.split_at(length); input.remaining = rest;
        let trace_json = JsonText::parse(std::str::from_utf8(text).map_err(|_| GuardianSignError::MalformedRequest)?.to_owned())?;
        let count = input.count(256)?;
        let mut deposit_anchors = Vec::with_capacity(count);
        for _ in 0..count {
            deposit_anchors.push(DepositAnchor { chain_index: input.u8()?, block_number: input.u64()?, block_hash: Hex(input.take()?), old_count: input.u32()?, new_count: input.u32()? });
        }
        let count = input.count(1024)?;
        let mut withdrawal_records = Vec::with_capacity(count);
        for _ in 0..count {
            withdrawal_records.push(WithdrawalBurnRecord { sender_user_id: input.u32()?, token_contract_id: input.u32()?, destination_chain_index: input.u8()?, token: input.words()?, amount: input.words()?, recipient: input.words()?, nonce: input.words()? });
        }
        if !input.remaining.is_empty() { return Err(GuardianSignError::MalformedRequest); }
        let request = Self { schema_version, authorization_version, network_magic, genesis_hash, user_id, session_nonce, operation, trace_json, deposit_anchors, withdrawal_records };
        request.validate()?;
        Ok(request)
    }
}

pub fn encode_u256(value: U256) -> [u8; 32] { value.to_le_bytes::<32>() }

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
    struct SourceOptional {
        required: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proof: Option<Vec<u8>>,
        ordinary_optional: Option<u32>,
    }

    #[test]
    fn canonical_json_obeys_source_omissions_and_rejects_unknown_or_duplicate_keys() {
        assert!(parse_canonical_json::<SourceOptional>(br#"{"required":1,"ordinary_optional":null}"#).is_ok());
        for invalid in [
            br#"{"required":1,"ordinary_optional":null,"proof":null}"#.as_slice(),
            br#"{"required":1}"#.as_slice(),
            br#"{"required":1,"ordinary_optional":null,"unknown":0}"#.as_slice(),
            br#"{"required":1,"required":2,"ordinary_optional":null}"#.as_slice(),
        ] { assert!(parse_canonical_json::<SourceOptional>(invalid).is_err()); }
        assert!(parse_canonical_json::<Value>(br#"{"nested":[{"x":1,"x":2}]}"#).is_err());
        assert!(parse_canonical_json::<Value>(br#"{"nested":{"x":1,"\u0078":2}}"#).is_err());
    }

    #[test]
    fn fixed_hex_rejects_short_long_uppercase_or_wrong_width() {
        assert_eq!(parse_canonical_json::<Hex<2>>(br#""0x00af""#).unwrap().0, [0, 175]);
        for text in ["\"0x\"", "\"0x00\"", "\"0x00af01\"", "\"00af\"", "\"0x00AF\"", "\"0x0\""] {
            assert!(parse_canonical_json::<Hex<2>>(text.as_bytes()).is_err());
        }
    }

    #[test]
    fn exact_json_whitespace_changes_journal_digest_not_typed_value() {
        let a = JsonText::<SourceOptional>::parse("{\"required\":1,\"ordinary_optional\":null}".into()).unwrap();
        let b = JsonText::<SourceOptional>::parse("{ \"required\":1, \"ordinary_optional\":null }".into()).unwrap();
        assert_eq!(serde_json::to_value(a.decode().unwrap()).unwrap(), serde_json::to_value(b.decode().unwrap()).unwrap());
        let mut left = Vec::new(); let mut right = Vec::new();
        put_text(&mut left, a.as_str()); put_text(&mut right, b.as_str());
        assert_ne!(sha256(&left), sha256(&right));
        assert_eq!(&left[..8], &(a.as_str().len() as u64).to_le_bytes());
        assert_eq!(&left[8..], a.as_str().as_bytes());
    }

    #[test]
    fn fixed_width_integer_hash_and_burn_wire_vectors() {
        let mut bytes = Vec::new(); put_text(&mut bytes, "\u{00e9}");
        assert_eq!(bytes, [2, 0, 0, 0, 0, 0, 0, 0, 0xc3, 0xa9]);
        let hash = QHashOut::from_values(1, 0x0102030405060708, 3, 4);
        let encoded = encode_hash(hash).unwrap();
        assert_eq!(&encoded[..8], &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&encoded[8..16], &[8, 7, 6, 5, 4, 3, 2, 1]);
        let mut noncanonical = hash; noncanonical.0.elements[0] = GoldilocksField(GOLDILOCKS_MODULUS);
        assert!(encode_hash(noncanonical).is_err());
        assert_eq!(encode_u256(U256::MAX), [255; 32]);
        assert_eq!(&encode_u256(U256::from(0x0102u64))[..4], &[2, 1, 0, 0]);
        let mut encoded = Vec::new(); burn(1).encode(&mut encoded);
        assert_eq!(encoded.len(), 137);
        assert_eq!(&encoded[..9], &[0xe8, 3, 0, 0, 4, 0, 0, 0, 0]);
        assert_eq!(&encoded[9 + 32 + 28..9 + 64], &[1, 0, 0, 0]);
        assert_eq!([GuardianOperation::Bridge as u8, GuardianOperation::Bootstrap as u8, GuardianOperation::ReplacePolicy as u8], [0, 1, 2]);
    }

    fn burn(amount: u64) -> WithdrawalBurnRecord {
        WithdrawalBurnRecord { sender_user_id: 1000, token_contract_id: 4, destination_chain_index: 0,
            token: [0; 8], amount: [0, 0, 0, 0, 0, 0, (amount >> 32) as u32, amount as u32],
            recipient: [0, 0, 0, 0, 0, 0, 0, 1], nonce: [0, 0, 0, 0, 0, 0, 0, 7] }
    }

    #[test]
    fn burn_integer_boundaries_and_address_width_do_not_reduce_modulo_field() {
        assert_eq!(burn(GOLDILOCKS_MODULUS - 1).amount_u64().unwrap(), GOLDILOCKS_MODULUS - 1);
        for amount in [0, GOLDILOCKS_MODULUS, GOLDILOCKS_MODULUS + 1, u64::MAX] { assert!(burn(amount).amount_u64().is_err()); }
        let mut record = burn(1); record.amount[0] = 1; assert!(record.amount_u64().is_err());
        assert_eq!(record.token_address().unwrap().0, [0; 20]);
        record.token[2] = 1; assert!(record.token_address().is_err());
        record.recipient = [0; 8]; assert!(record.recipient_address().is_err());
    }

    #[test]
    fn archive_index_cannot_replace_or_remove_approved_versions() {
        let old = GuardianAuthorizationIndex { active_version: 1, versions: vec![GuardianAuthorizationVersion { version: 1, sha256: sha256(b"old") }] };
        let mut next = old.clone(); next.active_version = 2;
        next.versions.push(GuardianAuthorizationVersion { version: 2, sha256: sha256(b"new") });
        assert!(old.validate_update(&next).is_ok());
        next.versions[0].sha256 = sha256(b"replacement"); assert!(old.validate_update(&next).is_err());
        next.versions.remove(0); assert!(old.validate_update(&next).is_err());
        assert_eq!(old.version(2).unwrap_err(), GuardianSignError::HistoryUnavailable);
        assert_eq!(old.resolve(1, b"wrong").unwrap_err(), GuardianSignError::AuthorizationMismatch);
        assert_eq!(old.archive_file(Path::new("archive"), 1).unwrap(), Path::new("archive/1.json"));
        assert!(GuardianAuthorizationIndex { active_version: 2, versions: old.versions.clone() }.validate().is_err());
        let mut duplicate = old.clone(); duplicate.versions.push(old.versions[0].clone()); assert!(duplicate.validate().is_err());
    }

    #[test]
    fn unavailable_errors_alone_advise_retry_without_halt_release() {
        for error in [GuardianSignError::EvidenceUnavailable, GuardianSignError::HistoryUnavailable, GuardianSignError::JournalUnavailable, GuardianSignError::KeyUnavailable] {
            assert_eq!(GuardianSignErrorResponse::new(None, error).retry_after_ms, 1000);
            assert_eq!(error.http_status(), 503);
        }
        assert_eq!(GuardianSignError::AccountHalted.retry_after_ms(), 0);
        assert_eq!(GuardianSignError::NonceConflict.http_status(), 409);
        assert_eq!(GuardianSignError::EvidenceMismatch.http_status(), 403);
    }

    #[test]
    fn endpoint_and_archive_paths_cannot_escape_or_embed_credentials() {
        for value in ["", "../archive", "/archive", "archive/../other"] { assert!(!relative_path(value)); }
        assert!(relative_path("archive/1.json"));
        assert!(validate_endpoint("https://history.example/", true).is_ok());
        assert!(validate_endpoint("http://127.0.0.1:9000/", true).is_ok());
        for value in ["http://history.example/", "https://user:secret@history.example/", "https://history.example/path", "https://history.example/?x=1"] {
            assert!(validate_endpoint(value, true).is_err());
        }
    }
}

#[cfg(test)]
pub(crate) fn codec_request_fixture() -> GuardianSignRequest {
    use psy_prover::trace::{TraceMeta, SessionAnchor, UpsStartWitness, TxFinalization};
    let trace = TxTrace {
        meta: TraceMeta { network_magic: 90101, user_id: BRIDGE_USER_ID, public_key: Hash4::ZERO },
        anchor: SessionAnchor { start_checkpoint_id: 0, checkpoint_leaf: Default::default(), global_state_roots: Default::default(), ups_step_circuit_whitelist_root: Hash4::ZERO },
        ups_start_witness: UpsStartWitness { ups_header: Default::default(), state_roots: Default::default(), checkpoint_tree_proof: Default::default(), user_tree_proof: Default::default(), user_registration_tree_proof: None, proof: None },
        contract_codes: vec![], steps: vec![],
        finalization: TxFinalization { submit_end_cap_input: Default::default(), nonce: GoldilocksField(1), tx_hash: Hash4::ZERO, software_defined_call: Default::default(), sig_hash: Hash4::ZERO },
    };
    let generated = GeneratedTxTraceJson::from_trace(&trace, serde_json::to_value(ContractCallData::new(vec![])).unwrap()).unwrap();
    GuardianSignRequest { schema_version: 1, authorization_version: 1, network_magic: 90101, genesis_hash: Hex([1; 32]), user_id: BRIDGE_USER_ID, session_nonce: 1, operation: GuardianOperation::Bootstrap, trace_json: JsonText::from_value(&generated).unwrap(), deposit_anchors: vec![], withdrawal_records: vec![] }
}

#[cfg(test)]
mod request_tests {
    use super::*;

    #[test]
    fn request_roundtrip_has_exact_header_widths_and_rejects_noncanonical_bytes() {
        let request = codec_request_fixture();
        let bytes = request.canonical_bytes().unwrap();
        assert_eq!(&bytes[..8], b"PSYGS001");
        assert_eq!(&bytes[8..16], &[1, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(&bytes[16..24], &90101u64.to_le_bytes());
        assert_eq!(&bytes[24..56], &[1; 32]);
        assert_eq!(&bytes[56..64], &524288u64.to_le_bytes());
        assert_eq!(&bytes[64..72], &1u64.to_le_bytes());
        assert_eq!(bytes[72], 1);
        assert_eq!(&bytes[73..81], &(request.trace_json.as_str().len() as u64).to_le_bytes());
        assert_eq!(&bytes[bytes.len() - 16..], &[0; 16]);
        assert_eq!(GuardianSignRequest::from_canonical_bytes(&bytes).unwrap().canonical_bytes().unwrap(), bytes);
        for length in [0, 7, 72, 80, bytes.len() - 1] { assert!(GuardianSignRequest::from_canonical_bytes(&bytes[..length]).is_err()); }
        let mut invalid = bytes.clone(); invalid.push(0); assert!(GuardianSignRequest::from_canonical_bytes(&invalid).is_err());
        let mut invalid = bytes.clone(); invalid[72] = 3; assert!(GuardianSignRequest::from_canonical_bytes(&invalid).is_err());
        let mut invalid = bytes; invalid[73..81].copy_from_slice(&u64::MAX.to_le_bytes()); assert!(GuardianSignRequest::from_canonical_bytes(&invalid).is_err());
    }

    #[test]
    fn nested_trace_omission_is_valid_but_unknown_and_precomputed_proofs_are_not() {
        let request = codec_request_fixture();
        assert!(request.decode_trace().unwrap().ups_start_witness.proof.is_none());
        let mut generated = request.trace_json.decode().unwrap();
        let mut trace: Value = serde_json::from_str(&generated.trace.payload).unwrap();
        trace["ups_start_witness"]["unknown"] = Value::Bool(true);
        generated.trace.payload = serde_json::to_string(&trace).unwrap();
        let mut invalid = request.clone(); invalid.trace_json = JsonText::from_value(&generated).unwrap();
        assert!(invalid.decode_trace().is_err());
        let mut trace = request.decode_trace().unwrap();
        trace.ups_start_witness.proof = Some(Default::default());
        generated.trace.payload = serde_json::to_string(&trace).unwrap();
        invalid.trace_json = JsonText::from_value(&generated).unwrap();
        assert!(invalid.decode_trace().is_err());
    }

    #[test]
    fn envelope_count_and_nonce_bind_full_trace_and_whitespace_binds_request() {
        let request = codec_request_fixture();
        let mut generated = request.trace_json.decode().unwrap();
        generated.tx_count = 1;
        let mut invalid = request.clone(); invalid.trace_json = JsonText::from_value(&generated).unwrap();
        assert!(invalid.validate().is_err());
        let mut invalid = request.clone(); invalid.session_nonce = 2; assert!(invalid.validate().is_err());
        let mut reformatted = request.clone();
        reformatted.trace_json = JsonText::parse(format!(" {} ", request.trace_json.as_str())).unwrap();
        assert!(traces_equal(&request.decode_trace().unwrap(), &reformatted.decode_trace().unwrap()).unwrap());
        assert_ne!(request.request_id().unwrap(), reformatted.request_id().unwrap());
    }
}

impl GuardianSignResponse {
    pub fn validate_context(&self, request: &GuardianSignRequest) -> Result<(), GuardianSignError> {
        if self.request_id != request.request_id()? || self.network_magic != request.network_magic || self.user_id != request.user_id
            || self.session_nonce != request.session_nonce { return Err(GuardianSignError::StateMismatch); }
        if self.member_index > 2 || !matches!(self.public_key.0[0], 2 | 3) { return Err(GuardianSignError::PolicyMismatch); }
        validate_hash(self.policy_commitment)
    }
}
impl GuardianSession {
    pub fn validate(&self, authorization: &GuardianAuthorization) -> Result<(), GuardianSignError> {
        let request = self.record.validate(authorization)?;
        if self.network_magic != request.network_magic || self.user_id != request.user_id || self.nonce != request.session_nonce
            || self.withdrawal_appends.len() != request.withdrawal_records.len() { return Err(GuardianSignError::StateMismatch); }
        validate_hash(self.starting_leaf_hash)?; validate_hash(self.ending_leaf_hash)?;
        let mut previous: Option<(u8, u32)> = None;
        for (append, burn) in self.withdrawal_appends.iter().zip(&request.withdrawal_records) {
            if append.burn != *burn || append.chain_index != burn.destination_chain_index { return Err(GuardianSignError::EvidenceMismatch); }
            if let Some((chain, index)) = previous {
                if chain == append.chain_index && index.checked_add(1) != Some(append.append_index) { return Err(GuardianSignError::StateMismatch); }
            }
            previous = Some((append.chain_index, append.append_index));
        }
        Ok(())
    }
}

#[cfg(test)]
mod bounds_tests {
    use super::*;

    #[test]
    fn request_vector_bounds_and_destination_nonce_uniqueness_are_enforced() {
        let mut request = codec_request_fixture(); request.operation = GuardianOperation::Bridge;
        request.deposit_anchors = (0..=256).map(|i| DepositAnchor { chain_index: i as u8, block_number: 1, block_hash: Hex([1; 32]), old_count: 0, new_count: 1 }).collect();
        assert_eq!(request.validate().unwrap_err(), GuardianSignError::MalformedRequest);
        request.deposit_anchors.clear();
        let burn = WithdrawalBurnRecord { sender_user_id: 1, token_contract_id: 4, destination_chain_index: 0, token: [0; 8], amount: [0, 0, 0, 0, 0, 0, 0, 1], recipient: [0, 0, 0, 0, 0, 0, 0, 1], nonce: [0; 8] };
        request.withdrawal_records = vec![burn.clone(); 1025];
        assert_eq!(request.validate().unwrap_err(), GuardianSignError::MalformedRequest);
        let mut other = burn.clone(); other.sender_user_id = 2;
        request.withdrawal_records = vec![burn, other];
        assert_eq!(request.validate().unwrap_err(), GuardianSignError::WithdrawalNonceConflict);
    }

    #[test]
    fn digest_is_standard_sha256_without_extra_domain() {
        assert_eq!(hex::encode(sha256(b"abc").0), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn proof_and_page_limits_are_not_request_size_estimates() {
        assert!(decode_hex("0x0001", 1).is_err());
        assert_eq!(decode_hex("0x0001", 2).unwrap(), [0, 1]);
        let request = JsonText::from_value(&codec_request_fixture()).unwrap();
        assert!(validate_future_endcap_proof_size(&request, &Default::default(), 0).is_err());
        assert!(validate_future_endcap_proof_size(&request, &Default::default(), u32::MAX).is_err());
        assert!(validate_future_endcap_proof_size(&request, &Default::default(), 1024).is_ok());
        let page = GuardianSessionsResponse { sessions: vec![], next_after_nonce: 7, has_more: false };
        assert!(page.validate_page(7, 1).is_ok());
        assert!(page.validate_page(6, 1).is_err());
        assert!(page.validate_page(7, 0).is_err());
        assert!(page.validate_page(7, 65).is_err());
    }
}

impl L2RpcEndpointPin {
    pub fn validate(&self) -> Result<url::Url, GuardianSignError> {
        let invalid = GuardianSignError::AuthorizationMismatch;
        let url = url::Url::parse(&self.rpc_url).map_err(|_| invalid)?;
        let (_, after_scheme) = self.rpc_url.split_once("://").ok_or(invalid)?;
        let raw_path = after_scheme.find('/').map(|i| &after_scheme[i..]).unwrap_or("");
        if self.rpc_url.contains('\\') || raw_path.contains('%') || raw_path.split('/').any(|segment| segment == "." || segment == "..")
            || self.rpc_url.chars().any(|c| c.is_control() || c.is_whitespace())
            || url.host().is_none() || !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
            return Err(invalid);
        }
        match (url.scheme(), url.host(), self.tls_certificate_sha256) {
            ("https", Some(_), Some(_)) => {}
            ("http", Some(url::Host::Ipv4(ip)), None) if ip == std::net::Ipv4Addr::LOCALHOST => {
                let authority = after_scheme.split('/').next().unwrap_or("");
                if authority.split(':').next() != Some("127.0.0.1") { return Err(invalid); }
            }
            ("http", Some(url::Host::Ipv6(ip)), None) if ip == std::net::Ipv6Addr::LOCALHOST => {
                let authority = after_scheme.split('/').next().unwrap_or("");
                if authority != "[::1]" && !authority.starts_with("[::1]:") { return Err(invalid); }
            }
            _ => return Err(invalid),
        }
        Ok(url)
    }
}
impl SigningAuthorization {
    pub fn validate(&self, authorization: &GuardianAuthorization, runtime: &GuardianRuntimeConfig, journal_public_key: Hex33, now_unix: u64) -> Result<(), GuardianSignError> {
        if !canonical_field(self.network_magic) || self.network_magic != authorization.network_magic || self.user_id != BRIDGE_USER_ID
            || self.user_id != authorization.user_id || self.public_key != journal_public_key || !matches!(self.public_key.0[0], 2 | 3)
            || !relative_path(&self.db_path) || self.db_path != runtime.db_path
            || !self.exclusive_key_use || !self.complete_journal || self.revoked || self.not_before_unix >= self.expires_at_unix
            || now_unix < self.not_before_unix || now_unix >= self.expires_at_unix { return Err(GuardianSignError::KeyUnavailable); }
        Ok(())
    }
}

#[cfg(test)]
mod runtime_pin_tests {
    use super::*;

    fn pin(url: &str, certificate: bool) -> L2RpcEndpointPin {
        L2RpcEndpointPin { role: L2RpcEndpointRole::Coordinator, config_id: 0, rpc_url: url.into(), tls_certificate_sha256: certificate.then_some(Hex([1; 32])) }
    }

    #[test]
    fn l2_route_approval_preserves_path_and_normalizes_origin_only() {
        assert_eq!(pin("https://NODE.example:443/realm/2", true).validate().unwrap().as_str(), "https://node.example/realm/2");
        assert_ne!(pin("https://node.example/realm/1", true).validate().unwrap(), pin("https://node.example/realm/2", true).validate().unwrap());
        assert!(pin("http://127.0.0.1:9000/", false).validate().is_ok());
        assert!(pin("http://[::1]:9000/", false).validate().is_ok());
        for url in ["http://localhost/", "http://127.0.0.2/", "http://127.1/", "http://2130706433/", "http://[0:0:0:0:0:0:0:1]/"] {
            assert!(pin(url, false).validate().is_err());
        }
    }

    #[test]
    fn l2_routes_reject_aliases_credentials_queries_and_wrong_pin_presence() {
        for url in ["https://node.example/a/../b", "https://node.example/a/./b", "https://node.example/%2e/b", "https://node.example/%61", "https://user:password@node.example/", "https://node.example/?q=1", "https://node.example/#fragment", "https://node.example/a\\b"] {
            assert!(pin(url, true).validate().is_err());
        }
        assert!(pin("https://node.example/", false).validate().is_err());
        assert!(pin("http://127.0.0.1/", true).validate().is_err());
        assert_eq!(L2RpcEndpointRole::Coordinator as u8, 0);
        assert_eq!(L2RpcEndpointRole::Realm as u8, 1);
        assert!(parse_canonical_json::<L2RpcEndpointPin>(br#"{"role":"Coordinator","config_id":0,"rpc_url":"https://node.example/","tls_certificate_sha256":null,"extra":true}"#).is_err());
    }
}

#[cfg(test)]
mod signing_authorization_tests {
    use super::*;
    use bincode::Options;

    #[test]
    fn signing_authorization_binds_key_path_interval_and_all_assertions() {
        let account = MultisigAccount { contract_id: 6, initial_policy: psy_vm::ups::multisig::MultisigPolicy {
            version: 1, threshold: 2, member_count: 3, member_hashes: [Hash4::ZERO; 8],
        } };
        let authorization = GuardianAuthorization {
            version: 1, network_magic: 90101, genesis_hash: Hex([1; 32]), user_id: BRIDGE_USER_ID,
            account_json: JsonText::from_value(&account).unwrap(), account_public_key: Hash4::ZERO, multisig_fingerprint: Hash4::ZERO,
            deposit_contract_id: 2, withdrawal_contract_id: 3, fee_contract_id: 0, guta_fee: 1, da_fee: 1, max_fee: 100,
            max_endcap_proof_bytes: 1024, approved_contracts: vec![], chains: vec![],
        };
        let runtime = GuardianRuntimeConfig {
            authorization_path: "archive/1.json".into(), authorization_archive_path: "archive".into(), authorization_index_path: "index.json".into(),
            rpc_config_path: "rpc.json".into(), listen_address: "127.0.0.1:9000".into(), tls_certificate_path: "tls.crt".into(),
            tls_private_key_path: "tls.key".into(), client_ca_path: "ca.crt".into(), allowed_client_certificate_sha256: vec![Hex([1; 32])],
            db_path: "guardian.redb".into(), signing_key_secret_path: "key.json".into(),
            signing_key_password_secret_path: "key.password".into(), signing_authorization_path: "signing-authorization.json".into(),
            l2_rpc_url: "http://127.0.0.1:9001/".into(), l2_rpc_endpoint_pins: vec![], l1_rpc_urls: vec![], history_urls: vec![],
        };
        let mut key = [1; 33]; key[0] = 2; let key = Hex(key);
        let approval = SigningAuthorization {
            network_magic: 90101, user_id: BRIDGE_USER_ID, public_key: key, db_path: "guardian.redb".into(),
            not_before_unix: 100, expires_at_unix: 200, exclusive_key_use: true, complete_journal: true, revoked: false,
        };
        assert!(approval.validate(&authorization, &runtime, key, 100).is_ok());
        assert!(approval.validate(&authorization, &runtime, key, 199).is_ok());
        for now in [99, 200, u64::MAX] { assert!(approval.validate(&authorization, &runtime, key, now).is_err()); }
        let mut wrong_key = key; wrong_key.0[1] ^= 1;
        assert!(approval.validate(&authorization, &runtime, wrong_key, 150).is_err());
        for mutation in 0..7 {
            let mut invalid = approval.clone();
            match mutation {
                0 => invalid.exclusive_key_use = false,
                1 => invalid.complete_journal = false,
                2 => invalid.revoked = true,
                3 => invalid.network_magic = GOLDILOCKS_MODULUS,
                4 => invalid.user_id += 1,
                5 => invalid.db_path = "other.redb".into(),
                _ => invalid.expires_at_unix = invalid.not_before_unix,
            }
            assert!(invalid.validate(&authorization, &runtime, key, 150).is_err());
        }
        let mut json = serde_json::to_value(&approval).unwrap(); json["connection_secret"] = Value::String("not permitted".into());
        assert!(parse_canonical_json::<SigningAuthorization>(&serde_json::to_vec(&json).unwrap()).is_err());
        for keep_db_path in [false, true] {
            let mut json = serde_json::to_value(&approval).unwrap();
            if !keep_db_path { json.as_object_mut().unwrap().remove("db_path"); }
            json["postgres_connection_secret_path"] = Value::String("database.secret".into());
            assert!(parse_canonical_json::<SigningAuthorization>(&serde_json::to_vec(&json).unwrap()).is_err());
            let mut json = serde_json::to_value(&runtime).unwrap();
            if !keep_db_path { json.as_object_mut().unwrap().remove("db_path"); }
            json["postgres_connection_secret_path"] = Value::String("database.secret".into());
            assert!(parse_canonical_json::<GuardianRuntimeConfig>(&serde_json::to_vec(&json).unwrap()).is_err());
        }
        for (old_key, new_key, value) in [("exclusive_custody", "exclusive_key_use", serde_json::to_value(&approval).unwrap()), ("custody_attestation_path", "signing_authorization_path", serde_json::to_value(&runtime).unwrap())] {
            let mut replaced = value.clone();
            let retained = replaced.as_object_mut().unwrap().remove(new_key).unwrap();
            replaced[old_key] = retained;
            let bytes = serde_json::to_vec(&replaced).unwrap();
            if old_key == "exclusive_custody" { assert!(parse_canonical_json::<SigningAuthorization>(&bytes).is_err()); }
            else { assert!(parse_canonical_json::<GuardianRuntimeConfig>(&bytes).is_err()); }
            let mut both = value;
            both[old_key] = both[new_key].clone();
            let bytes = serde_json::to_vec(&both).unwrap();
            if old_key == "exclusive_custody" { assert!(parse_canonical_json::<SigningAuthorization>(&bytes).is_err()); }
            else { assert!(parse_canonical_json::<GuardianRuntimeConfig>(&bytes).is_err()); }
        }
        let account = GuardianAccount { network_magic: 90101, user_id: BRIDGE_USER_ID, state: GuardianAccountState::Halted,
            last_checkpoint_id: 0, last_checkpoint_hash: Hash4::default(), imported_nonce: None, authorization_version: 1,
            halt_reason: Some(HaltReason::SigningAuthorizationInvalid) };
        let codec = bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes();
        let mut bytes = codec.serialize(&account).unwrap();
        let ordinal = bytes.len() - 4;
        bytes[ordinal..].copy_from_slice(&5u32.to_le_bytes());
        let decoded: GuardianAccount = codec.deserialize(&bytes).unwrap();
        assert_eq!(decoded.halt_reason, Some(HaltReason::SigningAuthorizationInvalid));
        for path in ["", "../guardian.redb", "/guardian.redb"] {
            let mut invalid = approval.clone(); invalid.db_path = path.into();
            let mut config = runtime.clone(); config.db_path = path.into();
            assert!(invalid.validate(&authorization, &config, key, 150).is_err());
        }
    }
}

#[cfg(test)]
mod compiler_artifact_tests {
    use super::*;

    fn approval() -> ApprovedContract {
        let artifact = CompilerArtifact {
            state_tree_height: 4, circuit_definitions: vec![],
            abi: serde_json::json!({ "schema_version": "2.0.0", "contract": { "name": "codec_fixture", "state_tree_height": 4, "state": [], "methods": [] }, "types": [] }),
        };
        let compiler_artifact_json = JsonText::from_value(&artifact).unwrap();
        let compiler_artifact_sha256 = sha256(compiler_artifact_json.as_str().as_bytes());
        ApprovedContract { contract_id: 6, contract_leaf_json: JsonText::from_value(&PsyContractLeaf::default()).unwrap(), compiler_artifact_json, compiler_artifact_sha256 }
    }

    #[test]
    fn artifact_digest_binds_exact_retained_bytes_not_reserialized_abi() {
        let mut approved = approval();
        assert_eq!(approved.compiler_artifact().unwrap().state_tree_height, 4);
        approved.compiler_artifact_json = JsonText::parse(format!(" {} ", approved.compiler_artifact_json.as_str())).unwrap();
        assert_eq!(approved.compiler_artifact().unwrap_err(), GuardianSignError::AuthorizationMismatch);
        approved.compiler_artifact_sha256 = sha256(approved.compiler_artifact_json.as_str().as_bytes());
        assert!(approved.compiler_artifact().is_ok());
    }

    #[test]
    fn artifact_requires_complete_exact_envelope_without_old_approval_fields() {
        let approved = approval();
        let value = serde_json::to_value(approved.compiler_artifact().unwrap()).unwrap();
        for field in ["state_tree_height", "circuit_definitions", "abi"] {
            let mut missing = value.clone(); missing.as_object_mut().unwrap().remove(field);
            assert!(JsonText::<CompilerArtifact>::parse(serde_json::to_string(&missing).unwrap()).is_err());
        }
        let mut unknown = value; unknown["extra"] = Value::Bool(true);
        assert!(JsonText::<CompilerArtifact>::parse(serde_json::to_string(&unknown).unwrap()).is_err());
        let mut old_schema = serde_json::to_value(&approved).unwrap();
        old_schema["compiler_abi_json"] = Value::String("{}".into());
        assert!(parse_canonical_json::<ApprovedContract>(&serde_json::to_vec(&old_schema).unwrap()).is_err());
    }

    #[test]
    fn artifact_abi_version_and_height_must_match_approval_shape() {
        for (version, height) in [("1.0.0", 4), ("2.0.0", 5)] {
            let mut approved = approval(); let mut artifact = approved.compiler_artifact().unwrap();
            artifact.abi["schema_version"] = version.into(); artifact.abi["contract"]["state_tree_height"] = height.into();
            approved.compiler_artifact_json = JsonText::from_value(&artifact).unwrap();
            approved.compiler_artifact_sha256 = sha256(approved.compiler_artifact_json.as_str().as_bytes());
            assert_eq!(approved.compiler_artifact().unwrap_err(), GuardianSignError::AuthorizationMismatch);
        }
    }

    #[test]
    fn full_abi_retains_array_length_above_u32_without_layout_generation() {
        let mut approved = approval(); let mut artifact = approved.compiler_artifact().unwrap();
        artifact.abi["contract"]["state"] = serde_json::json!([{
            "name": "other_user_info", "offset": 1, "felt_size": 8589934592u64,
            "type": { "kind": "array", "item": { "kind": "primitive", "name": "Felt" }, "length": 4294967296u64, "item_felt_size": 2 }
        }]);
        approved.compiler_artifact_json = JsonText::from_value(&artifact).unwrap();
        approved.compiler_artifact_sha256 = sha256(approved.compiler_artifact_json.as_str().as_bytes());
        assert_eq!(approved.compiler_artifact().unwrap().abi["contract"]["state"][0]["type"]["length"].as_u64(), Some(4294967296));
    }
}
