use std::{collections::BTreeSet, fmt, marker::PhantomData, net::SocketAddr, path::PathBuf};

use alloy_primitives::U256;
use plonky2::{field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}}, hash::poseidon::PoseidonHash};
use psy_client_common::{args::ContractCallData, data::qhashout::QHashOut};
use psy_client_data::{config::store_config::PsyHasher, guta::end_cap_input::SubmitUserEndCapNonProofInput, qdata::contract::PsyContractLeaf};
use psy_config::ChainEndpoint;
use psy_crypto::hash::{core::sha256::CoreSha256Hasher, traits::hasher::{FieldQHasher, MerkleZeroHasher}};
use psy_prover::trace::{GeneratedTxTraceJson, TxTrace, TraceStep};
use psy_vm::ups::multisig::{MultisigAccount, MultisigSignatures, MULTISIG_POLICY_CONTRACT_ID};
use serde::{de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor}, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

pub const MAX_BODY_BYTES: usize = 128 * 1024 * 1024;
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
pub fn parse_duplicate_free_json(bytes: &[u8]) -> Result<Value, GuardianSignError> {
    if bytes.len() > MAX_BODY_BYTES { return Err(GuardianSignError::MalformedRequest); }
    let UniqueJson(parsed) = serde_json::from_slice(bytes).map_err(|_| GuardianSignError::MalformedRequest)?;
    Ok(parsed)
}
pub fn parse_canonical_json<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<T, GuardianSignError> {
    let parsed = parse_duplicate_free_json(bytes)?;
    let typed: T = serde_json::from_value(parsed.clone()).map_err(|_| GuardianSignError::MalformedRequest)?;
    if serde_json::to_value(&typed).map_err(|_| GuardianSignError::MalformedRequest)? != parsed {
        return Err(GuardianSignError::MalformedRequest);
    }
    Ok(typed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardianSignError {
    MalformedRequest, UnauthorizedCaller, AccountIdentityConflict, AuthorizationMismatch,
    L1RpcUnavailable, L2RpcUnavailable, DepositLogsUnavailable, SignatureQuorumUnavailable, FinalityPending, CheckpointProofUnavailable,
    DatabaseUnavailable, SessionHistoryUnavailable, ObserverTimeout, SigningPreparationTimeout, SigningBusy, ListenerUnavailable, SignalHandlerUnavailable,
    IndexCheckpointTimeout,
    ProofMismatch, TraceMismatch, DepositMismatch, WithdrawalMismatch, L1ResponseMismatch,
    StateMismatch, UnsupportedCall, PolicyMismatch,
    NonceConflict, WithdrawalNonceConflict, KeyUnavailable, AccountHalted,
}
impl fmt::Display for GuardianSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for GuardianSignError {}
impl GuardianSignError {
    pub fn http_status(self) -> u16 {
        match self {
            Self::MalformedRequest => 400, Self::UnauthorizedCaller => 401,
            Self::AccountIdentityConflict | Self::UnsupportedCall | Self::PolicyMismatch
                | Self::ProofMismatch | Self::TraceMismatch | Self::DepositMismatch | Self::WithdrawalMismatch | Self::L1ResponseMismatch => 403,
            Self::AuthorizationMismatch | Self::StateMismatch | Self::NonceConflict | Self::WithdrawalNonceConflict => 409,
            Self::L1RpcUnavailable | Self::L2RpcUnavailable | Self::DepositLogsUnavailable | Self::SignatureQuorumUnavailable | Self::FinalityPending | Self::CheckpointProofUnavailable
                | Self::DatabaseUnavailable | Self::SessionHistoryUnavailable | Self::ObserverTimeout | Self::SigningPreparationTimeout | Self::SigningBusy
                | Self::IndexCheckpointTimeout | Self::KeyUnavailable | Self::AccountHalted | Self::ListenerUnavailable | Self::SignalHandlerUnavailable => 503,
        }
    }
    pub fn retry_after_ms(self) -> u32 {
        match self {
            Self::L1RpcUnavailable | Self::L2RpcUnavailable | Self::DepositLogsUnavailable | Self::SignatureQuorumUnavailable | Self::FinalityPending | Self::CheckpointProofUnavailable
                | Self::DatabaseUnavailable | Self::SessionHistoryUnavailable | Self::ObserverTimeout | Self::SigningPreparationTimeout | Self::SigningBusy
                | Self::IndexCheckpointTimeout | Self::KeyUnavailable => 1000,
            Self::MalformedRequest | Self::UnauthorizedCaller | Self::AccountIdentityConflict | Self::AuthorizationMismatch
                | Self::ProofMismatch | Self::TraceMismatch | Self::DepositMismatch | Self::WithdrawalMismatch | Self::L1ResponseMismatch
                | Self::StateMismatch | Self::UnsupportedCall | Self::PolicyMismatch | Self::NonceConflict | Self::WithdrawalNonceConflict
                | Self::AccountHalted | Self::ListenerUnavailable | Self::SignalHandlerUnavailable => 0,
        }
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
    /// Compiler method bindings authenticated by the retained authorization digest.
    pub methods: Vec<ApprovedMethod>,
    pub withdrawal_layout: Option<WithdrawalLayout>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedMethod {
    pub name: String,
    pub method_id: u32,
    pub input_felt_count: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithdrawalLayout {
    /// Felt offset of the first withdrawal record in user state.
    pub subslot_base: u64,
    pub capacity: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianAuthorization {
    pub genesis_hash: Hex32,
    pub bridge_relayer_signing_policy: JsonText<MultisigAccount>,
    pub multisig_fingerprint: Hash4,
    pub endcap_verifier_fingerprint: Hash4,
    pub max_fee: u64,
    pub approved_contracts: Vec<ApprovedContract>, pub chains: Vec<ChainAuthorization>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainAuthorization {
    pub chain_index: u8, pub chain_id: U256, pub genesis_hash: Hex32,
    pub bridge: Hex20, pub state_manager: Hex20, pub deployment_block: u64,
    pub token_mappings: Vec<TokenMapping>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenMapping { pub token: Hex20, pub l2_contract_id: u32 }

/// Selected canonical network and derived operator-local startup values. Not serialized.
#[derive(Debug, Clone)]
pub struct GuardianConfig {
    pub network: psy_config::NetworkConfigGoldilocks,
    pub authorization: std::sync::Arc<GuardianAuthorization>,
    pub guardian_root: PathBuf,
    pub endpoints: [String; 3],
    pub history_url: String,
}
/// Derived startup fields for one selected guardian. Not serialized.
#[derive(Debug, Clone)]
pub struct GuardianRuntimeConfig {
    pub listen_address: String,
    pub db_path: String,
    pub signing_key_secret_path: String,
    pub signing_key_password_secret_path: String,
    pub l2_rpc_url: String,
    pub l1_rpc_urls: Vec<ChainEndpoint>,
    pub history_urls: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum GuardianOperation { Bridge = 0, Bootstrap = 1, ReplacePolicy = 2 }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianSignRequest {
    pub schema_version: u32, pub authorization_sha256: Hex32, pub network_magic: u64,
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
    pub request_bytes: Vec<u8>, pub starting_leaf_hash: Hash4,
    pub ending_leaf_hash: Hash4, pub message: [u8; 32],
    /// Deposit tree states changed by this exact request. A reservation binds them; inclusion never advances until import.
    pub deposit_tree_states: Vec<DepositTreeState>,
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
pub enum HaltReason { FinalityConflict, CheckpointConflict, NonceConsumedDifferently, IncludedTransitionMissing, AppendHistoryMismatch }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianAccount {
    pub network_magic: u64, pub user_id: u64, pub state: GuardianAccountState,
    pub last_checkpoint_id: u64, pub last_checkpoint_hash: Hash4, pub imported_nonce: Option<u64>,
    pub authorization_sha256: Hex32, pub imported_ending_leaf: Option<Hash4>,
    /// One included withdrawal frontier per destination chain: (chain, count, frontier, root).
    pub withdrawal_chains: Vec<(u8, u32, [Hash4; 32], Hash4)>,
    pub halt_reason: Option<HaltReason>,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositTreeState {
    pub count: u32,
    pub frontier: [Hash4; 32],
    pub root: Hash4,
    pub anchor: DepositAnchor,
    pub event_block: u64,
    pub previous_count: u32,
    pub previous_root: Hash4,
    pub occupied_partial_page_hashes: Vec<Hash4>,
}
impl DepositTreeState {
    pub fn empty(chain_index: u8) -> Self {
        Self { count: 0, frontier: [Hash4::ZERO; 32], root: <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32), anchor: DepositAnchor { chain_index, block_number: 0, block_hash: Hex([0; 32]), old_count: 0, new_count: 0 }, event_block: 0, previous_count: 0, previous_root: <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32), occupied_partial_page_hashes: Vec::new() }
    }
    pub fn extends(&self, anchor: &DepositAnchor) -> bool { self.count == anchor.old_count && self.anchor.block_number <= anchor.block_number && self.occupied_partial_page_hashes.len() == (self.count % 32) as usize }
    pub fn occupied_partial_page_hashes(&self) -> &[Hash4] { &self.occupied_partial_page_hashes }
    pub fn with_occupied(mut self, hashes: Vec<Hash4>) -> Self { self.occupied_partial_page_hashes = hashes; self }
    pub fn matches_opening(&self, chain_index: u8, count: u32, root: [u64; 4]) -> bool { self.anchor.chain_index == chain_index && self.count == count && self.root.0.elements.map(|limb| limb.to_canonical_u64()) == root }
    pub fn validate(&self) -> Result<(), GuardianSignError> {
        if self.occupied_partial_page_hashes.len() != (self.count % 32) as usize
            || (self.count != 0 && (self.previous_count >= self.count || self.anchor.old_count != self.previous_count || self.anchor.new_count != self.count || self.anchor.block_hash.0 == [0; 32])) {
            return Err(GuardianSignError::DepositMismatch);
        }
        validate_hash(self.root)?; validate_hash(self.previous_root)?;
        for hash in self.frontier.iter().chain(&self.occupied_partial_page_hashes) { validate_hash(*hash)?; }
        if self.count == 0 {
            if self.frontier != [Hash4::ZERO; 32] || self.root != <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32) { return Err(GuardianSignError::DepositMismatch); }
        } else if frontier_root(self.count, &self.frontier) != self.root {
            return Err(GuardianSignError::DepositMismatch);
        }
        Ok(())
    }
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
        if self.amount[..6] != [0; 6] || !canonical_field(amount) { return Err(GuardianSignError::WithdrawalMismatch); }
        Ok(amount)
    }
    pub fn token_address(&self) -> Result<Hex20, GuardianSignError> { Self::address(&self.token) }
    pub fn recipient_address(&self) -> Result<Hex20, GuardianSignError> {
        let address = Self::address(&self.recipient)?;
        if address.0 == [0; 20] { return Err(GuardianSignError::WithdrawalMismatch); }
        Ok(address)
    }
    fn address(words: &[u32; 8]) -> Result<Hex20, GuardianSignError> {
        if words[..3] != [0; 3] { return Err(GuardianSignError::WithdrawalMismatch); }
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
        if self.schema_version != 1 || self.authorization_sha256.0 == [0; 32] || !canonical_field(self.network_magic) || self.user_id != BRIDGE_USER_ID || !canonical_field(self.session_nonce)
            || self.deposit_anchors.len() > 256 || self.withdrawal_records.len() > 1024 { return Err(GuardianSignError::MalformedRequest); }
        if self.operation != GuardianOperation::Bridge && (!self.deposit_anchors.is_empty() || !self.withdrawal_records.is_empty()) { return Err(GuardianSignError::UnsupportedCall); }
        if self.operation == GuardianOperation::Bridge && self.deposit_anchors.is_empty() && self.withdrawal_records.is_empty() { return Err(GuardianSignError::UnsupportedCall); }
        if self.deposit_anchors.windows(2).any(|w| w[0].chain_index >= w[1].chain_index)
            || self.deposit_anchors.iter().any(|a| a.new_count <= a.old_count || a.block_hash.0 == [0; 32]) { return Err(GuardianSignError::DepositMismatch); }
        if self.withdrawal_records.windows(2).any(|w| w[0].selection_key() >= w[1].selection_key()) { return Err(GuardianSignError::WithdrawalMismatch); }
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
        bytes.extend_from_slice(&self.schema_version.to_le_bytes()); bytes.extend_from_slice(&self.authorization_sha256.0);
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
        if self.authorization_sha256 != authorization.digest()? || self.genesis_hash != authorization.genesis_hash || self.user_id != authorization.user_id() { return Err(GuardianSignError::AuthorizationMismatch); }
        if self.decode_trace()?.meta.public_key != authorization.account_public_key()? { return Err(GuardianSignError::AccountIdentityConflict); }
        for anchor in &self.deposit_anchors { authorization.chain(anchor.chain_index)?; }
        for record in &self.withdrawal_records {
            let token = record.token_address()?;
            if !authorization.chain(record.destination_chain_index)?.token_mappings.iter().any(|m| m.token == token && m.l2_contract_id == record.token_contract_id) { return Err(GuardianSignError::WithdrawalMismatch); }
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
    pub fn user_id(&self) -> u64 { BRIDGE_USER_ID }
    pub fn account_public_key(&self) -> Result<Hash4, GuardianSignError> {
        let account = self.bridge_relayer_signing_policy.decode()?;
        let param = account.public_key_param().map_err(|_| GuardianSignError::PolicyMismatch)?;
        Ok(QHashOut(PoseidonHash::two_to_one(self.multisig_fingerprint.0, param.0)))
    }
    pub fn digest(&self) -> Result<Hex32, GuardianSignError> {
        serde_json::to_vec(self).map(|bytes| sha256(&bytes)).map_err(|_| GuardianSignError::AuthorizationMismatch)
    }

    pub fn resolve_signed_authorization(&self, signed: &GuardianSigned) -> Result<&Self, GuardianSignError> {
        signed.validate()?;
        let request = GuardianSignRequest::from_canonical_bytes(&signed.request_bytes)?;
        if request.authorization_sha256 != self.digest()? || request.user_id != self.user_id() || request.genesis_hash != self.genesis_hash {
            return Err(GuardianSignError::AuthorizationMismatch);
        }
        Ok(self)
    }
    pub fn chain(&self, index: u8) -> Result<&ChainAuthorization, GuardianSignError> {
        self.chains.binary_search_by_key(&index, |c| c.chain_index).ok().map(|i| &self.chains[i]).ok_or(GuardianSignError::AuthorizationMismatch)
    }
    pub fn validate(&self, guta_fee: u64, da_fee: u64) -> Result<(), GuardianSignError> {
        let mismatch = GuardianSignError::AuthorizationMismatch;
        let floor = guta_fee.checked_add(da_fee).ok_or(mismatch)?;
        if self.genesis_hash.0 == [0; 32] || self.max_fee < floor
            || self.chains.is_empty() || self.chains.len() > 256 { return Err(mismatch); }
        validate_hash(self.account_public_key()?)?; validate_hash(self.multisig_fingerprint)?; validate_hash(self.endcap_verifier_fingerprint)?;
        if self.endcap_verifier_fingerprint == Hash4::ZERO { return Err(mismatch); }
        let account = self.bridge_relayer_signing_policy.decode()?;
        if account.contract_id != MULTISIG_POLICY_CONTRACT_ID || account.initial_policy.threshold != 2 || account.initial_policy.member_count != 3 { return Err(GuardianSignError::PolicyMismatch); }
        for member in account.initial_policy.member_hashes { validate_hash(member)?; }
        if self.multisig_fingerprint == Hash4::ZERO { return Err(GuardianSignError::AccountIdentityConflict); }
        if self.approved_contracts.windows(2).any(|w| w[0].contract_id >= w[1].contract_id) || self.chains.windows(2).any(|w| w[0].chain_index >= w[1].chain_index) { return Err(mismatch); }
        let approved: BTreeSet<_> = self.approved_contracts.iter().map(|c| c.contract_id).collect();
        if [0, MULTISIG_POLICY_CONTRACT_ID, 2, 3].iter().any(|id| !approved.contains(id)) { return Err(mismatch); }
        let mut chain_ids = BTreeSet::new();
        for chain in &self.chains {
            if chain.chain_id == U256::ZERO || !chain_ids.insert(chain.chain_id) || chain.genesis_hash.0 == [0; 32]
                || [chain.bridge, chain.state_manager].iter().any(|a| a.0 == [0; 20])
                || chain.token_mappings.is_empty() || chain.token_mappings.len() > 65536
                || chain.token_mappings.windows(2).any(|w| w[0].token >= w[1].token) { return Err(mismatch); }
            for mapping in &chain.token_mappings {
                if !approved.contains(&mapping.l2_contract_id) { return Err(mismatch); }
            }
        }
        for contract in &self.approved_contracts {
            contract.contract_leaf_json.decode()?;
            let mut method_names = BTreeSet::new();
            let mut method_ids = BTreeSet::new();
            for method in &contract.methods {
                if !method_names.insert(&method.name) || !method_ids.insert(method.method_id) { return Err(mismatch); }
            }
            if let Some(layout) = contract.withdrawal_layout {
                if layout.capacity == 0 || layout.subslot_base % 4 != 0 || layout.subslot_base.checked_add(layout.capacity.checked_mul(4).ok_or(mismatch)?).is_none() { return Err(mismatch); }
            }
        }
        Ok(())
    }
}


/// L1 endpoints retain HTTPS-or-loopback. Guardian and history origins are HTTP only.
pub fn validate_endpoint(value: &str, origin_only: bool, http_only: bool) -> Result<(), GuardianSignError> {
    let url = url::Url::parse(value).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(), Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) => host == "localhost", None => false,
    };
    let scheme_ok = if http_only {
        url.scheme() == "http" && url.port().is_none_or(|port| port != 0)
    } else {
        url.scheme() == "https" || (url.scheme() == "http" && loopback)
    };
    if !scheme_ok || url.host().is_none() || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some()
        || (origin_only && (url.path() != "/" || url.query().is_some())) { return Err(GuardianSignError::AuthorizationMismatch); }
    Ok(())
}
pub(crate) fn http_origin(value: &str) -> Result<String, GuardianSignError> {
    let url = url::Url::parse(value).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
    validate_endpoint(value, true, true)?;
    if matches!(url.host(), Some(url::Host::Ipv4(ip)) if ip.is_unspecified())
        || matches!(url.host(), Some(url::Host::Ipv6(ip)) if ip.is_unspecified()) {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
    let port = url.port().unwrap_or(80);
    let host = url.host_str().ok_or(GuardianSignError::AuthorizationMismatch)?.to_ascii_lowercase();
    Ok(format!("http://{host}:{port}"))
}
pub(crate) fn history_origin(address: SocketAddr) -> Result<String, GuardianSignError> {
    if address.ip().is_unspecified() || address.port() == 0 { return Err(GuardianSignError::AuthorizationMismatch); }
    let origin = if address.is_ipv6() { format!("http://[{}]:{}/", address.ip(), address.port()) } else { format!("http://{address}/") };
    validate_endpoint(&origin, true, true)?;
    Ok(origin)
}
impl GuardianRuntimeConfig {
    pub fn validate(&self, authorization: &GuardianAuthorization) -> Result<(), GuardianSignError> {
        if self.listen_address.parse::<SocketAddr>().is_err()
            || self.history_urls.is_empty() || self.l1_rpc_urls.len() != authorization.chains.len() { return Err(GuardianSignError::AuthorizationMismatch); }
        let mut history = BTreeSet::new();
        for endpoint in &self.history_urls {
            validate_endpoint(endpoint, true, true)?;
            if !history.insert(endpoint) { return Err(GuardianSignError::AuthorizationMismatch); }
        }
        let mut chains = BTreeSet::new();
        for endpoint in &self.l1_rpc_urls {
            authorization.chain(endpoint.chain_index)?;
            if !chains.insert(endpoint.chain_index) { return Err(GuardianSignError::AuthorizationMismatch); }
            validate_endpoint(&endpoint.rpc_url, false, false)?;
        }
        Ok(())
    }
}

impl GuardianSigned {
    pub fn validate(&self) -> Result<(), GuardianSignError> {
        if !canonical_field(self.network_magic) || self.user_id != BRIDGE_USER_ID || !canonical_field(self.nonce)
            || self.request_bytes.len() > MAX_BODY_BYTES || self.deposit_tree_states.len() > 256 { return Err(GuardianSignError::DatabaseUnavailable); }
        let request = GuardianSignRequest::from_canonical_bytes(&self.request_bytes).map_err(|_| GuardianSignError::DatabaseUnavailable)?;
        if request.network_magic != self.network_magic || request.user_id != self.user_id || request.session_nonce != self.nonce {
            return Err(GuardianSignError::DatabaseUnavailable);
        }
        validate_changed_deposit_tree_states(&request, &self.deposit_tree_states)?;
        validate_hash(self.starting_leaf_hash)?; validate_hash(self.ending_leaf_hash)?;
        Ok(())
    }
}
impl GuardianAccount {
    pub fn validate(&self) -> Result<(), GuardianSignError> {
        if !canonical_field(self.network_magic) || self.user_id != BRIDGE_USER_ID
            || self.imported_nonce.is_some_and(|n| !canonical_field(n))
            || self.authorization_sha256.0 == [0; 32]
            || (self.imported_nonce.is_none()) != self.imported_ending_leaf.is_none()
            || self.withdrawal_chains.len() > 256
            || self.withdrawal_chains.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || (self.state == GuardianAccountState::Halted) != self.halt_reason.is_some() { return Err(GuardianSignError::DatabaseUnavailable); }
        validate_hash(self.last_checkpoint_hash)?;
        if let Some(leaf) = self.imported_ending_leaf { validate_hash(leaf)?; }
        for (_, count, frontier, root) in &self.withdrawal_chains {
            validate_hash(*root)?;
            for hash in frontier { validate_hash(*hash)?; }
            if *count == 0 {
                if *frontier != [Hash4::ZERO; 32] || *root != <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32) { return Err(GuardianSignError::DatabaseUnavailable); }
            } else if frontier_root(*count, frontier) != *root {
                return Err(GuardianSignError::DatabaseUnavailable);
            }
        }
        Ok(())
    }
}
pub fn validate_changed_deposit_tree_states(request: &GuardianSignRequest, deposit_tree_states: &[DepositTreeState]) -> Result<(), GuardianSignError> {
    if deposit_tree_states.len() != request.deposit_anchors.len() { return Err(GuardianSignError::DepositMismatch); }
    for (deposit_tree_state, anchor) in deposit_tree_states.iter().zip(&request.deposit_anchors) {
        deposit_tree_state.validate()?;
        if deposit_tree_state.anchor != *anchor || deposit_tree_state.count != anchor.new_count || deposit_tree_state.previous_count != anchor.old_count { return Err(GuardianSignError::DepositMismatch); }
    }
    Ok(())
}
/// Applies one included session to the sole account checkpoint, one deposit tree state per chain, and one withdrawal frontier per chain.
/// `included_deposit_tree_states` is the full included map. The caller proved `checkpoint_hash` is the bound checkpoint leaf. This does not halt or touch indexes.
pub fn advance_included_account(account: &GuardianAccount, included_deposit_tree_states: &[DepositTreeState], session: &GuardianSession, deposit_tree_states: &[DepositTreeState], checkpoint_id: u64, checkpoint_hash: Hash4) -> Result<(GuardianAccount, Vec<DepositTreeState>), GuardianSignError> {
    let request = session.record.request_json.decode()?;
    if request.authorization_sha256 != account.authorization_sha256 { return Err(GuardianSignError::AuthorizationMismatch); }
    let next = account.imported_nonce.unwrap_or(0).checked_add(1).ok_or(GuardianSignError::SessionHistoryUnavailable)?;
    if session.nonce != next { return Err(GuardianSignError::SessionHistoryUnavailable); }
    if session.record.included_checkpoint_id != checkpoint_id || session.record.included_checkpoint_hash != checkpoint_hash {
        return Err(GuardianSignError::StateMismatch);
    }
    validate_hash(checkpoint_hash)?;
    validate_changed_deposit_tree_states(&request, deposit_tree_states)?;
    if checkpoint_id < account.last_checkpoint_id || (checkpoint_id == account.last_checkpoint_id && checkpoint_hash != account.last_checkpoint_hash) {
        return Err(GuardianSignError::StateMismatch);
    }
    if account.imported_ending_leaf.is_some_and(|leaf| leaf != session.starting_leaf_hash) { return Err(GuardianSignError::StateMismatch); }
    let mut chains = account.withdrawal_chains.clone();
    for append in &session.withdrawal_appends {
        let index = chains.binary_search_by_key(&append.chain_index, |chain| chain.0).unwrap_or_else(|index| index);
        if index == chains.len() || chains[index].0 != append.chain_index {
            chains.insert(index, (append.chain_index, 0, [Hash4::ZERO; 32], <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32)));
        }
        let chain = &mut chains[index];
        if append.append_index != chain.1 { return Err(GuardianSignError::StateMismatch); }
        chain.1 = chain.1.checked_add(1).ok_or(GuardianSignError::StateMismatch)?;
        chain.3 = append_merkle_leaf(&mut chain.2, append.append_index, withdrawal_tree_leaf(&append.burn));
    }
    let mut included = included_deposit_tree_states.to_vec();
    included.sort_by_key(|deposit_tree_state| deposit_tree_state.anchor.chain_index);
    if included.windows(2).any(|pair| pair[0].anchor.chain_index == pair[1].anchor.chain_index) { return Err(GuardianSignError::DatabaseUnavailable); }
    for deposit_tree_state in deposit_tree_states {
        let index = included.binary_search_by_key(&deposit_tree_state.anchor.chain_index, |saved| saved.anchor.chain_index).unwrap_or_else(|index| index);
        let saved = if index < included.len() && included[index].anchor.chain_index == deposit_tree_state.anchor.chain_index { included[index].clone() } else { DepositTreeState::empty(deposit_tree_state.anchor.chain_index) };
        if !saved.extends(&deposit_tree_state.anchor) || saved.root != deposit_tree_state.previous_root { return Err(GuardianSignError::StateMismatch); }
        if index < included.len() && included[index].anchor.chain_index == deposit_tree_state.anchor.chain_index { included[index] = deposit_tree_state.clone(); }
        else { included.insert(index, deposit_tree_state.clone()); }
    }
    let mut advanced = account.clone();
    advanced.last_checkpoint_id = checkpoint_id;
    advanced.last_checkpoint_hash = checkpoint_hash;
    advanced.imported_nonce = Some(session.nonce);
    advanced.imported_ending_leaf = Some(session.ending_leaf_hash);
    advanced.withdrawal_chains = chains;
    advanced.validate()?;
    Ok((advanced, included))
}


pub fn append_merkle_leaf(frontier: &mut [Hash4; 32], index: u32, leaf: Hash4) -> Hash4 {
    let mut current = leaf;
    let mut zero = Hash4::ZERO;
    for (level, left) in frontier.iter_mut().enumerate() {
        if (index >> level) & 1 == 0 { *left = current; current = PsyHasher::q_two_to_one(current, zero); }
        else { current = PsyHasher::q_two_to_one(*left, current); }
        zero = PsyHasher::q_two_to_one(zero, zero);
    }
    current
}
/// Recomputes the 32-level root from the count-selected frontier nodes. A zero count is only the real zero tree, never an absent opening.
pub fn frontier_root(count: u32, frontier: &[Hash4; 32]) -> Hash4 {
    if count == 0 { return <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32); }
    let mut current = Hash4::ZERO;
    let mut zero = Hash4::ZERO;
    for level in 0..32 {
        if (count >> level) & 1 != 0 { current = PsyHasher::q_two_to_one(frontier[level], current); }
        else { current = PsyHasher::q_two_to_one(current, zero); }
        zero = PsyHasher::q_two_to_one(zero, zero);
    }
    current
}

pub fn withdrawal_tree_leaf(record: &WithdrawalBurnRecord) -> Hash4 {
    let mut fields = [GoldilocksField::ZERO; 34];
    fields[0] = GoldilocksField::from_canonical_u32(record.sender_user_id);
    for (target, words) in fields[1..33].chunks_exact_mut(8).zip([&record.recipient, &record.token, &record.amount, &record.nonce]) {
        for (target, word) in target.iter_mut().zip(words) { *target = GoldilocksField::from_canonical_u32(*word); }
    }
    fields[33] = GoldilocksField::from_canonical_u8(record.destination_chain_index);
    PsyHasher::q_hash_many(&fields)
}


impl GuardianSessionRecord {
    pub fn validate(&self, authorization: &GuardianAuthorization) -> Result<GuardianSignRequest, GuardianSignError> {
        let request = self.request_json.decode()?;
        request.validate_authorization(authorization)?;
        validate_hash(self.included_checkpoint_hash)?;
        let signatures = self.signatures_json.decode()?;
        if signatures.member_indices.len() != 2 || signatures.signatures.len() != 2
            || signatures.member_indices[0] >= signatures.member_indices[1] || signatures.member_indices[1] > 2 { return Err(GuardianSignError::PolicyMismatch); }
        if self.proof_bytes()?.is_empty() { return Err(GuardianSignError::SessionHistoryUnavailable); }
        self.endcap_input_json.decode()?;
        let page = GuardianSessionsResponse { sessions: vec![self.clone()], next_after_nonce: request.session_nonce, has_more: false };
        page.to_bytes()?;
        Ok(request)
    }
    pub fn proof_bytes(&self) -> Result<Vec<u8>, GuardianSignError> {
        decode_hex(&self.endcap_proof_hex, MAX_BODY_BYTES)
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
            if request.session_nonce <= nonce { return Err(GuardianSignError::SessionHistoryUnavailable); }
            nonce = request.session_nonce;
        }
        if self.next_after_nonce != nonce { return Err(GuardianSignError::SessionHistoryUnavailable); }
        Ok(())
    }
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
        let schema_version = input.u32()?; let authorization_sha256 = Hex(input.take()?);
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
        let request = Self { schema_version, authorization_sha256, network_magic, genesis_hash, user_id, session_nonce, operation, trace_json, deposit_anchors, withdrawal_records };
        request.validate()?;
        Ok(request)
    }
}

pub fn encode_u256(value: U256) -> [u8; 32] { value.to_le_bytes::<32>() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_checkpoint_timeout_uses_existing_unavailable_retry_policy() {
        assert_eq!(GuardianSignError::IndexCheckpointTimeout.http_status(), 503);
        assert_eq!(GuardianSignError::IndexCheckpointTimeout.retry_after_ms(), 1000);
    }

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
    fn unavailable_errors_alone_advise_retry_without_halt_release() {
        for error in [GuardianSignError::L2RpcUnavailable, GuardianSignError::SessionHistoryUnavailable, GuardianSignError::DatabaseUnavailable, GuardianSignError::KeyUnavailable] {
            assert_eq!(GuardianSignErrorResponse::new(None, error).retry_after_ms, 1000);
            assert_eq!(error.http_status(), 503);
        }
        assert_eq!(GuardianSignError::AccountHalted.retry_after_ms(), 0);
        assert_eq!(GuardianSignError::NonceConflict.http_status(), 409);
        assert_eq!(GuardianSignError::ProofMismatch.http_status(), 403);
    }

    #[test]
    fn endpoints_cannot_embed_credentials() {
        assert!(validate_endpoint("http://history.example/", true, true).is_ok());
        assert!(validate_endpoint("http://127.0.0.1:9000/", true, true).is_ok());
        assert!(validate_endpoint("http://[::1]:9000/", true, true).is_ok());
        assert!(validate_endpoint("https://history.example/", true, true).is_err());
        for value in ["http://user:secret@history.example/", "http://history.example/path", "http://history.example/?x=1", "http://history.example/#fragment", "http://127.0.0.1:0/"] {
            assert!(validate_endpoint(value, true, true).is_err());
        }
        assert!(validate_endpoint("https://l1.example/rpc", false, false).is_ok());
        assert!(validate_endpoint("http://history.example/rpc", false, false).is_err());
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
    GuardianSignRequest { schema_version: 1, authorization_sha256: approval_tests::authorization_fixture().digest().unwrap(), network_magic: 90101, genesis_hash: Hex([1; 32]), user_id: BRIDGE_USER_ID, session_nonce: 1, operation: GuardianOperation::Bootstrap, trace_json: JsonText::from_value(&generated).unwrap(), deposit_anchors: vec![], withdrawal_records: vec![] }
}

#[cfg(test)]
mod request_tests {
    use super::*;

    #[test]
    fn request_roundtrip_has_exact_header_widths_and_rejects_noncanonical_bytes() {
        let request = codec_request_fixture();
        let bytes = request.canonical_bytes().unwrap();
        assert_eq!(&bytes[..8], b"PSYGS001");
        assert_eq!(&bytes[8..12], &1u32.to_le_bytes());
        assert_eq!(&bytes[12..44], &request.authorization_sha256.0);
        assert_eq!(&bytes[44..52], &90101u64.to_le_bytes());
        assert_eq!(&bytes[52..84], &[1; 32]);
        assert_eq!(&bytes[84..92], &524288u64.to_le_bytes());
        assert_eq!(&bytes[92..100], &1u64.to_le_bytes());
        assert_eq!(bytes[100], 1);
        assert_eq!(&bytes[101..109], &(request.trace_json.as_str().len() as u64).to_le_bytes());
        assert_eq!(&bytes[bytes.len() - 16..], &[0; 16]);
        assert_eq!(GuardianSignRequest::from_canonical_bytes(&bytes).unwrap().canonical_bytes().unwrap(), bytes);
        for length in [0, 7, 100, 108, bytes.len() - 1] { assert!(GuardianSignRequest::from_canonical_bytes(&bytes[..length]).is_err()); }
        let mut invalid = bytes.clone(); invalid.push(0); assert!(GuardianSignRequest::from_canonical_bytes(&invalid).is_err());
        let mut invalid = bytes.clone(); invalid[100] = 3; assert!(GuardianSignRequest::from_canonical_bytes(&invalid).is_err());
        let mut invalid = bytes; invalid[101..109].copy_from_slice(&u64::MAX.to_le_bytes()); assert!(GuardianSignRequest::from_canonical_bytes(&invalid).is_err());
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
            if append.burn != *burn || append.chain_index != burn.destination_chain_index { return Err(GuardianSignError::WithdrawalMismatch); }
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
        let page = GuardianSessionsResponse { sessions: vec![], next_after_nonce: 7, has_more: false };
        assert!(page.validate_page(7, 1).is_ok());
        assert!(page.validate_page(6, 1).is_err());
        assert!(page.validate_page(7, 0).is_err());
        assert!(page.validate_page(7, 65).is_err());
    }
}

#[cfg(test)]
pub(crate) mod approval_tests {
    use super::*;

    fn approval() -> ApprovedContract {
        ApprovedContract {
            contract_id: MULTISIG_POLICY_CONTRACT_ID,
            contract_leaf_json: JsonText::from_value(&PsyContractLeaf::default()).unwrap(),
            methods: vec![], withdrawal_layout: None,
        }
    }

    #[test]
    fn authorization_is_one_minimal_object_with_deterministic_digest() {
        let authorization = authorization_fixture();
        let value = serde_json::to_value(&authorization).unwrap();
        let fields = value.as_object().unwrap().keys().map(String::as_str).collect::<BTreeSet<_>>();
        assert_eq!(fields, BTreeSet::from(["genesis_hash", "bridge_relayer_signing_policy", "multisig_fingerprint", "endcap_verifier_fingerprint", "max_fee", "approved_contracts", "chains"]));
        let pretty = serde_json::to_vec_pretty(&authorization).unwrap();
        assert_eq!(GuardianAuthorization::parse(&pretty).unwrap().digest().unwrap(), authorization.digest().unwrap());
        let mut changed = authorization.clone(); changed.max_fee += 1;
        assert_ne!(changed.digest().unwrap(), authorization.digest().unwrap());
        for field in ["version", "account_json", "network_magic", "max_endcap_proof_bytes"] {
            let mut old = value.clone(); old[field] = serde_json::json!(1);
            assert!(GuardianAuthorization::parse(&serde_json::to_vec(&old).unwrap()).is_err());
        }
    }

    #[test]
    fn compact_approval_rejects_compiler_payload_and_unknown_fields() {
        let mut value = serde_json::to_value(approval()).unwrap();
        value["compiler_artifact_json"] = Value::String("{}".into());
        assert!(parse_canonical_json::<ApprovedContract>(&serde_json::to_vec(&value).unwrap()).is_err());
        value.as_object_mut().unwrap().remove("compiler_artifact_json");
        value["withdrawal_layout"] = serde_json::json!({"subslot_base": 12, "capacity": 4294967296u64});
        let approved: ApprovedContract = parse_canonical_json(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(approved.withdrawal_layout.unwrap().capacity, 4294967296);
    }

    #[test]
    fn approved_methods_require_unique_names_and_ids_without_guessed_input_bounds() {
        let mut auth = authorization_fixture();
        let first = ApprovedMethod { name: "withdraw".into(), method_id: 7, input_felt_count: u32::MAX };
        let second = ApprovedMethod { name: "deposit".into(), method_id: 8, input_felt_count: 0 };
        auth.approved_contracts[0].methods = vec![first.clone(), second.clone()];
        assert!(auth.validate(1, 1).is_ok());
        auth.approved_contracts[0].methods[1].name = first.name;
        assert_eq!(auth.validate(1, 1).unwrap_err(), GuardianSignError::AuthorizationMismatch);
        auth.approved_contracts[0].methods[1] = second;
        auth.approved_contracts[0].methods[1].method_id = first.method_id;
        assert_eq!(auth.validate(1, 1).unwrap_err(), GuardianSignError::AuthorizationMismatch);
    }

    #[test]
    fn approved_method_fields_are_required_and_unknown_fields_are_rejected() {
        let method = ApprovedMethod { name: "withdraw".into(), method_id: 7, input_felt_count: 4 };
        let value = serde_json::to_value(&method).unwrap();
        for field in ["name", "method_id", "input_felt_count"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(parse_canonical_json::<ApprovedMethod>(&serde_json::to_vec(&missing).unwrap()).is_err());
        }
        let mut unknown = value;
        unknown["unapproved"] = Value::Bool(true);
        assert!(parse_canonical_json::<ApprovedMethod>(&serde_json::to_vec(&unknown).unwrap()).is_err());
        let mut contract = serde_json::to_value(approval()).unwrap();
        contract.as_object_mut().unwrap().remove("methods");
        assert!(parse_canonical_json::<ApprovedContract>(&serde_json::to_vec(&contract).unwrap()).is_err());
    }
    pub(crate) fn authorization_fixture() -> GuardianAuthorization {
        use psy_vm::ups::multisig::{MultisigPolicy, MULTISIG_POLICY_CONTRACT_ID};
        let mut members = [Hash4::ZERO; 8];
        members[0] = Hash4::from_values(1, 0, 0, 0);
        members[1] = Hash4::from_values(2, 0, 0, 0);
        members[2] = Hash4::from_values(3, 0, 0, 0);
        let account = MultisigAccount { contract_id: MULTISIG_POLICY_CONTRACT_ID, initial_policy: MultisigPolicy { version: 1, threshold: 2, member_count: 3, member_hashes: members } };
        let fingerprint = Hash4::from_values(9, 8, 7, 6);
        let approved_contracts = [0, MULTISIG_POLICY_CONTRACT_ID, 2, 3].into_iter().map(|contract_id| { let mut contract = approval(); contract.contract_id = contract_id; contract }).collect();
        GuardianAuthorization {
            genesis_hash: Hex([1; 32]),
            bridge_relayer_signing_policy: JsonText::from_value(&account).unwrap(),
            multisig_fingerprint: fingerprint, max_fee: 2,
            endcap_verifier_fingerprint: Hash4::from_values(1, 1, 1, 1), approved_contracts,
            chains: vec![ChainAuthorization {
                chain_index: 0, chain_id: U256::from(1u64), genesis_hash: Hex([2; 32]), bridge: Hex([3; 20]), state_manager: Hex([4; 20]),
                deployment_block: 1, token_mappings: vec![TokenMapping { token: Hex([11; 20]), l2_contract_id: 0 }],
            }],
        }
    }

    #[test]
    fn contract1_authorization_is_accepted_and_contract6_is_rejected() {
        let mut auth = authorization_fixture();
        let account = auth.bridge_relayer_signing_policy.decode().unwrap();
        assert!(auth.validate(1, 1).is_ok());
        auth.approved_contracts.retain(|contract| contract.contract_id != MULTISIG_POLICY_CONTRACT_ID);
        assert_eq!(auth.validate(1, 1).unwrap_err(), GuardianSignError::AuthorizationMismatch);
        auth.approved_contracts = [0, 2, 3, 6].into_iter().map(|contract_id| { let mut contract = approval(); contract.contract_id = contract_id; contract }).collect();
        let mut wrong = account; wrong.contract_id = 6;
        auth.bridge_relayer_signing_policy = JsonText::from_value(&wrong).unwrap();
        assert_eq!(auth.validate(1, 1).unwrap_err(), GuardianSignError::PolicyMismatch);
    }
}
