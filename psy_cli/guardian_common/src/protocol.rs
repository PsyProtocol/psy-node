use std::{collections::BTreeSet, fmt, marker::PhantomData, net::SocketAddr, path::PathBuf};

use alloy_primitives::U256;
use plonky2::{field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}}, hash::poseidon::PoseidonHash};
use psy_client_common::{args::ContractCallData, data::qhashout::QHashOut};
use psy_client_data::{config::store_config::PsyHasher, guta::end_cap_input::SubmitUserEndCapNonProofInput};

use psy_crypto::hash::{core::sha256::CoreSha256Hasher, traits::hasher::{FieldQHasher, MerkleZeroHasher}};
use psy_prover::trace::{GeneratedTxTraceJson, TxTrace, TraceStep};
use psy_vm::ups::multisig::{MultisigAccount, MultisigPolicy, MultisigSignatures, MULTISIG_POLICY_CONTRACT_ID};
use serde::{de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor}, Deserialize, Deserializer, Serialize, Serializer};
use base64::{engine::general_purpose::STANDARD as STANDARD_B64, Engine as _};
use serde_json::Value;

/// Outer storage/HTTP envelope. Distinct from the inner `PSYGS002` request domain.
pub const RECORD_MAGIC: [u8; 8] = *b"PSYGR001";
pub const RECORD_VERSION: u32 = 1;
pub const RECORD_HEADER_LEN: usize = 20;
pub const RECORD_COMPRESSION_LEVEL: i32 = 3;

/// Versioned zstd envelope around exact inner bytes. Canonical for database rows and HTTP bodies.
///
/// Layout, little-endian: `PSYGR001` (8) | version `1` (u32) | uncompressed length (u64) | one zstd frame.
pub fn encode_record(bytes: &[u8]) -> Result<Vec<u8>, GuardianSignError> {
    let length = u64::try_from(bytes.len()).map_err(|_| GuardianSignError::MalformedRequest)?;
    let compressed = zstd::stream::encode_all(bytes, RECORD_COMPRESSION_LEVEL).map_err(|_| GuardianSignError::MalformedRequest)?;
    let total = RECORD_HEADER_LEN.checked_add(compressed.len()).ok_or(GuardianSignError::MalformedRequest)?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&RECORD_MAGIC);
    frame.extend_from_slice(&RECORD_VERSION.to_le_bytes());
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&compressed);
    Ok(frame)
}

/// Inverse of `encode_record`. Returns the original inner bytes or `MalformedRequest`.
pub fn decode_record(bytes: &[u8]) -> Result<Vec<u8>, GuardianSignError> {
    if bytes.len() < RECORD_HEADER_LEN { return Err(GuardianSignError::MalformedRequest); }
    if bytes[..8] != RECORD_MAGIC || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) != RECORD_VERSION {
        return Err(GuardianSignError::MalformedRequest);
    }
    let advertised = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
    let advertised = usize::try_from(advertised).map_err(|_| GuardianSignError::MalformedRequest)?;
    let zstd_frame = &bytes[RECORD_HEADER_LEN..];
    if zstd_frame.len() < 4 || zstd_frame[..4] != zstd::zstd_safe::MAGICNUMBER.to_le_bytes() { return Err(GuardianSignError::MalformedRequest); }
    let mut decoder = zstd::stream::read::Decoder::with_buffer(zstd_frame).map_err(|_| GuardianSignError::MalformedRequest)?.single_frame();
    // Reading one byte past the advertised length reveals excess decoded output instead of
    // silently truncating it. Checked addition: an unrepresentable allowance is malformed input,
    // not an implicit size ceiling.
    let allowance = advertised.checked_add(1).ok_or(GuardianSignError::MalformedRequest)?;
    let mut output = Vec::new();
    {
        let mut reader = std::io::Read::take(&mut decoder, allowance as u64);
        let mut chunk = [0u8; 8192];
        loop {
            let read = std::io::Read::read(&mut reader, &mut chunk).map_err(|_| GuardianSignError::MalformedRequest)?;
            if read == 0 { break; }
            let decoded_len = output.len().checked_add(read).ok_or(GuardianSignError::MalformedRequest)?;
            if decoded_len > advertised { return Err(GuardianSignError::MalformedRequest); }
            output.try_reserve(read).map_err(|_| GuardianSignError::MalformedRequest)?;
            output.extend_from_slice(&chunk[..read]);
        }
    }
    if output.len() != advertised { return Err(GuardianSignError::MalformedRequest); }
    if !decoder.finish().is_empty() { return Err(GuardianSignError::MalformedRequest); }
    Ok(output)
}

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
        let bytes = decode_hex(&text).map_err(de::Error::custom)?;
        if bytes.len() != N { return Err(de::Error::custom("invalid fixed hex width")); }
        let mut result = [0; N];
        result.copy_from_slice(&bytes);
        Ok(Self(result))
    }
}
fn decode_hex(text: &str) -> Result<Vec<u8>, GuardianSignError> {
    let raw = text.strip_prefix("0x").ok_or(GuardianSignError::MalformedRequest)?;
    if raw.len() % 2 != 0 || !raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
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
    DatabaseUnavailable, SessionHistoryUnavailable, ObserverTimeout, SigningBusy, ListenerUnavailable, SignalHandlerUnavailable,
    IndexCheckpointTimeout,
    ProofMismatch, TraceMismatch, DepositMismatch, WithdrawalMismatch, L1ResponseMismatch,
    StateMismatch, UnsupportedCall, PolicyMismatch,
    NonceConflict, WithdrawalNonceConflict, KeyUnavailable, AccountHalted,
    LegacyJournalSchema,
}
impl fmt::Display for GuardianSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::LegacyJournalSchema { return f.write_str("incompatible legacy journal schema; explicit operator-controlled migration is required"); }
        write!(f, "{self:?}")
    }
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
                | Self::DatabaseUnavailable | Self::SessionHistoryUnavailable | Self::ObserverTimeout | Self::SigningBusy
                | Self::IndexCheckpointTimeout | Self::KeyUnavailable | Self::AccountHalted | Self::ListenerUnavailable | Self::SignalHandlerUnavailable | Self::LegacyJournalSchema => 503,
        }
    }
    pub fn retry_after_ms(self) -> u32 {
        match self {
            Self::L1RpcUnavailable | Self::L2RpcUnavailable | Self::DepositLogsUnavailable | Self::SignatureQuorumUnavailable | Self::FinalityPending | Self::CheckpointProofUnavailable
                | Self::DatabaseUnavailable | Self::SessionHistoryUnavailable | Self::ObserverTimeout | Self::SigningBusy
                | Self::IndexCheckpointTimeout | Self::KeyUnavailable => 1000,
            Self::MalformedRequest | Self::UnauthorizedCaller | Self::AccountIdentityConflict | Self::AuthorizationMismatch
                | Self::ProofMismatch | Self::TraceMismatch | Self::DepositMismatch | Self::WithdrawalMismatch | Self::L1ResponseMismatch
                | Self::StateMismatch | Self::UnsupportedCall | Self::PolicyMismatch | Self::NonceConflict | Self::WithdrawalNonceConflict
                | Self::AccountHalted | Self::ListenerUnavailable | Self::SignalHandlerUnavailable | Self::LegacyJournalSchema => 0,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianSignErrorResponse { pub request_id: Option<Hex32>, pub code: GuardianSignError, pub retry_after_ms: u32 }
impl GuardianSignErrorResponse {
    pub fn new(request_id: Option<Hex32>, code: GuardianSignError) -> Self { Self { request_id, code, retry_after_ms: code.retry_after_ms() } }
}

/// Selected canonical network and derived operator-local startup values. Not serialized.
#[derive(Debug, Clone)]
pub struct GuardianConfig {
    pub network: psy_config::NetworkConfigGoldilocks,
    pub guardian_root: PathBuf,
    pub endpoints: [String; 3],
    pub history_url: String,
    /// Chains parsed from the selected deployment documents. Not a config field.
    pub l1_chains: Vec<ChainEndpoint>,
}
/// One L1 the guardian dials. Built from a deployment document, never serialized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEndpoint {
    pub chain_index: u8,
    pub chain_id: U256,
    pub bridge: Hex20,
    /// Inclusive cold-scan bound from the selected Bridge deployment metadata, never configuration.
    pub deployment_block: u64,
    pub rpc_url: String,
}
/// Derived startup fields for one selected guardian. Not serialized.
#[derive(Debug, Clone)]
pub struct GuardianRuntimeConfig {
    pub listen_address: String,
    pub db_path: String,
    pub signing_key_secret_path: String,
    pub signing_key_password_env: String,
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
    pub schema_version: u32, pub network_magic: u64,
    pub user_id: u64, pub session_nonce: u64, pub operation: GuardianOperation,
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
#[serde(deny_unknown_fields)]
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
    pub account_public_key: Hash4, pub imported_ending_leaf: Option<Hash4>,
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
    /// Canonical amount check for the full uint256 the L2 withdrawal leaf
    /// binds and the L1 payout pays. Any nonzero 8-word amount is valid; the
    /// L2 withdraw method already rejects zero, so a zero record here is a
    /// mismatch, not a field-order cap.
    pub fn validate_amount(&self) -> Result<(), GuardianSignError> {
        if self.amount == [0; 8] { return Err(GuardianSignError::WithdrawalMismatch); }
        Ok(())
    }
    pub fn token_address(&self) -> Result<Hex20, GuardianSignError> { Self::address(&self.token) }
    /// Canonical 160-bit conversion. High bits are rejected, not truncated.
    /// A zero recipient is accepted; L1 classifies that slot.
    pub fn recipient_address(&self) -> Result<Hex20, GuardianSignError> { Self::address(&self.recipient) }
    fn address(words: &[u32; 8]) -> Result<Hex20, GuardianSignError> {
        if words[..3] != [0; 3] { return Err(GuardianSignError::WithdrawalMismatch); }
        let mut address = [0; 20];
        for (part, word) in address.chunks_exact_mut(4).zip(&words[3..]) { part.copy_from_slice(&word.to_be_bytes()); }
        Ok(Hex(address))
    }
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.sender_user_id.to_le_bytes()); bytes.extend_from_slice(&self.token_contract_id.to_le_bytes());
        bytes.push(self.destination_chain_index);
        for words in [&self.token, &self.amount, &self.recipient, &self.nonce] { put_words(bytes, words); }
    }
}
impl GuardianSignRequest {
    /// Wire entry for canonical JSON sign bodies: schema 3 only. Schema 2 stays a
    /// retained-row reader format; it is never signed again and keeps its request id.
    pub fn parse(bytes: &[u8]) -> Result<Self, GuardianSignError> {
        let request = Self::parse_retained(bytes)?;
        if request.schema_version != 3 { return Err(GuardianSignError::MalformedRequest); }
        Ok(request)
    }
    /// Retained-row JSON reader (archive restore, retained history text): accepts
    /// schema 2 and 3. Never call this on a live sign body; `parse` is the wire gate.
    pub fn parse_retained(bytes: &[u8]) -> Result<Self, GuardianSignError> {
        let request: Self = parse_canonical_json(bytes)?;
        request.validate()?;
        Ok(request)
    }
    pub fn validate(&self) -> Result<(), GuardianSignError> {
        if !matches!(self.schema_version, 2 | 3) || !canonical_field(self.network_magic) || self.user_id != BRIDGE_USER_ID || !canonical_field(self.session_nonce)
            || self.deposit_anchors.len() > 256 || self.withdrawal_records.len() > 1024 { return Err(GuardianSignError::MalformedRequest); }
        if self.operation != GuardianOperation::Bridge && (!self.deposit_anchors.is_empty() || !self.withdrawal_records.is_empty()) { return Err(GuardianSignError::UnsupportedCall); }
        if self.operation == GuardianOperation::Bridge && self.deposit_anchors.is_empty() && self.withdrawal_records.is_empty() { return Err(GuardianSignError::UnsupportedCall); }
        if self.deposit_anchors.windows(2).any(|w| w[0].chain_index >= w[1].chain_index)
            || self.deposit_anchors.iter().any(|a| a.new_count <= a.old_count || a.block_hash.0 == [0; 32]) { return Err(GuardianSignError::DepositMismatch); }
        for record in &self.withdrawal_records { record.validate_amount()?; }
        self.decode_trace()?;
        Ok(())
    }
    pub fn decode_trace(&self) -> Result<TxTrace, GuardianSignError> {
        let envelope = self.trace_json.decode()?;
        if envelope.trace.encoding != "json" { return Err(GuardianSignError::MalformedRequest); }
        // Schema 3 payloads already carry base64 byte paths. A retained schema-2 payload
        // is rewritten in memory only; the stored text and its request id are never modified.
        let payload = match self.schema_version {
            3 => envelope.trace.payload,
            2 => rewrite_schema2_trace_payload(&envelope.trace.payload)?,
            _ => return Err(GuardianSignError::MalformedRequest),
        };
        let trace: TxTrace = parse_canonical_json(payload.as_bytes())?;
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
        bytes.extend_from_slice(b"PSYGS002");
        bytes.extend_from_slice(&self.schema_version.to_le_bytes());
        bytes.extend_from_slice(&self.network_magic.to_le_bytes());
        bytes.extend_from_slice(&self.user_id.to_le_bytes()); bytes.extend_from_slice(&self.session_nonce.to_le_bytes()); bytes.push(self.operation as u8);
        put_text(&mut bytes, self.trace_json.as_str());
        bytes.extend_from_slice(&(self.deposit_anchors.len() as u64).to_le_bytes());
        for a in &self.deposit_anchors { bytes.push(a.chain_index); bytes.extend_from_slice(&a.block_number.to_le_bytes()); bytes.extend_from_slice(&a.block_hash.0); bytes.extend_from_slice(&a.old_count.to_le_bytes()); bytes.extend_from_slice(&a.new_count.to_le_bytes()); }
        bytes.extend_from_slice(&(self.withdrawal_records.len() as u64).to_le_bytes());
        for record in &self.withdrawal_records { record.encode(&mut bytes); }
        Ok(bytes)
    }
    pub fn request_id(&self) -> Result<Hex32, GuardianSignError> { Ok(sha256(&self.canonical_bytes()?)) }
    pub fn validate_authorization(&self, config: &GuardianConfig) -> Result<(), GuardianSignError> {
        self.validate()?;
        if self.network_magic != config.network_magic()? || self.user_id != BRIDGE_USER_ID { return Err(GuardianSignError::AccountIdentityConflict); }
        if self.decode_trace()?.meta.public_key != config.account_public_key()? { return Err(GuardianSignError::AccountIdentityConflict); }
        for anchor in &self.deposit_anchors { config.chain(anchor.chain_index)?; }
        for record in &self.withdrawal_records { config.chain(record.destination_chain_index)?; }
        Ok(())
    }
}
/// Rewrites a retained schema-2 trace payload in memory: the seven human-readable
/// byte paths move from JSON integer arrays (strict 0..=255) into padded standard
/// base64 (`base64` 0.22 `STANDARD`, the exact text the codec's strict decode
/// accepts), then the canonical typed parse runs unchanged. A string, object,
/// float, negative, or integer above 255 at a listed path is `MalformedRequest`;
/// arrays off the seven paths are never touched.
fn rewrite_schema2_trace_payload(payload: &str) -> Result<String, GuardianSignError> {
    let mut trace = parse_duplicate_free_json(payload.as_bytes())?;
    rewrite_schema2_trace(&mut trace)?;
    serde_json::to_string(&trace).map_err(|_| GuardianSignError::MalformedRequest)
}

fn rewrite_schema2_trace(trace: &mut Value) -> Result<(), GuardianSignError> {
    if let Some(record) = trace.get_mut("ups_start_witness").and_then(Value::as_object_mut)
        .and_then(|witness| witness.get_mut("proof")).and_then(Value::as_object_mut) {
        if let Some(proof) = record.get_mut("proof") { rewrite_schema2_bytes(proof)?; }
    }
    if let Some(codes) = trace.get_mut("contract_codes").and_then(Value::as_array_mut) {
        for code in codes {
            if let Some(field) = code.as_object_mut().and_then(|object| object.get_mut("code")) { rewrite_schema2_bytes(field)?; }
        }
    }
    let Some(steps) = trace.get_mut("steps").and_then(Value::as_array_mut) else { return Ok(()) };
    for step in steps {
        let Some(step) = step.as_object_mut() else { continue };
        match step.get("kind").and_then(Value::as_str) {
            Some("standard" | "burn_fee" | "inlined" | "deferred") => {
                if let Some(proof) = step.get_mut("proof").and_then(Value::as_object_mut) {
                    for path in ["cfc_proof", "ups_proof"] {
                        if let Some(field) = proof.get_mut(path) { rewrite_schema2_bytes(field)?; }
                    }
                }
            }
            Some("external_proof") => {
                if let Some(field) = step.get_mut("proof") { rewrite_schema2_bytes(field)?; }
            }
            Some("zk_sign") => {
                if let Some(field) = step.get_mut("sign_witness") { rewrite_schema2_bytes(field)?; }
                if let Some(source) = step.get_mut("sign_circuit_source").and_then(Value::as_object_mut) {
                    if source.get("kind").and_then(Value::as_str) == Some("psy_software_defined") {
                        if let Some(field) = source.get_mut("circuit_def") { rewrite_schema2_bytes(field)?; }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn rewrite_schema2_bytes(field: &mut Value) -> Result<(), GuardianSignError> {
    let Some(items) = field.as_array() else { return Err(GuardianSignError::MalformedRequest) };
    let mut bytes = Vec::with_capacity(items.len());
    for item in items {
        let byte = item.as_u64().filter(|byte| *byte <= u64::from(u8::MAX)).ok_or(GuardianSignError::MalformedRequest)?;
        bytes.push(byte as u8);
    }
    *field = Value::String(STANDARD_B64.encode(bytes));
    Ok(())
}
pub fn sha256(bytes: &[u8]) -> Hex32 { Hex(CoreSha256Hasher::hash_bytes(bytes).0) }
pub fn traces_equal(supplied: &TxTrace, replayed: &TxTrace) -> Result<bool, GuardianSignError> {
    Ok(serde_json::to_value(supplied).map_err(|_| GuardianSignError::MalformedRequest)? == serde_json::to_value(replayed).map_err(|_| GuardianSignError::MalformedRequest)?)
}

/// Derives the existing multisig account without retaining a second config representation.
pub fn initial_account(network: &psy_config::NetworkConfigGoldilocks) -> Result<MultisigAccount, GuardianSignError> {
    let members = network.guardian_initial_member_hashes.ok_or(GuardianSignError::PolicyMismatch)?;
    for member in members { validate_hash(member)?; }
    let mut member_hashes = [Hash4::ZERO; 8];
    member_hashes[..3].copy_from_slice(&members);
    let account = MultisigAccount { contract_id: MULTISIG_POLICY_CONTRACT_ID, initial_policy: MultisigPolicy { version: 1, threshold: 2, member_count: 3, member_hashes } };
    account.initial_policy.validate().map_err(|_| GuardianSignError::PolicyMismatch)?;
    account.public_key_param().map_err(|_| GuardianSignError::PolicyMismatch)?;
    Ok(account)
}

pub fn multisig_fingerprint() -> Result<Hash4, GuardianSignError> {
    psy_prover::wallet::memory_wallet::get_multisig_fingerprint::<GoldilocksField>().map_err(|_| GuardianSignError::PolicyMismatch)
}

impl GuardianConfig {
    pub fn initial_account(&self) -> Result<MultisigAccount, GuardianSignError> { initial_account(&self.network) }
    pub fn user_id(&self) -> u64 { BRIDGE_USER_ID }
    pub fn account_public_key(&self) -> Result<Hash4, GuardianSignError> {
        let param = self.initial_account()?.public_key_param().map_err(|_| GuardianSignError::PolicyMismatch)?;
        Ok(QHashOut(PoseidonHash::two_to_one(multisig_fingerprint()?.0, param.0)))
    }
    pub fn chain(&self, index: u8) -> Result<&ChainEndpoint, GuardianSignError> {
        self.l1_chains.iter().find(|chain| chain.chain_index == index).ok_or(GuardianSignError::AuthorizationMismatch)
    }
    pub fn validate_signed(&self, signed: &GuardianSigned) -> Result<(), GuardianSignError> {
        signed.validate()?;
        GuardianSignRequest::from_canonical_bytes(&signed.request_bytes)?.validate_authorization(self)
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
    pub fn validate(&self, config: &GuardianConfig) -> Result<(), GuardianSignError> {
        if self.listen_address.parse::<SocketAddr>().is_err()
            || self.history_urls.is_empty() || self.l1_rpc_urls.len() != config.l1_chains.len() { return Err(GuardianSignError::AuthorizationMismatch); }
        let mut history = BTreeSet::new();
        for endpoint in &self.history_urls {
            validate_endpoint(endpoint, true, true)?;
            if !history.insert(endpoint) { return Err(GuardianSignError::AuthorizationMismatch); }
        }
        let mut chains = BTreeSet::new();
        for endpoint in &self.l1_rpc_urls {
            config.chain(endpoint.chain_index)?;
            if !chains.insert(endpoint.chain_index) { return Err(GuardianSignError::AuthorizationMismatch); }
            validate_endpoint(&endpoint.rpc_url, false, false)?;
        }
        Ok(())
    }
}

impl GuardianSigned {
    pub fn validate(&self) -> Result<(), GuardianSignError> {
        if !canonical_field(self.network_magic) || self.user_id != BRIDGE_USER_ID || !canonical_field(self.nonce)
            || self.deposit_tree_states.len() > 256 { return Err(GuardianSignError::DatabaseUnavailable); }
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
            || self.account_public_key == Hash4::ZERO
            || (self.imported_nonce.is_none()) != self.imported_ending_leaf.is_none()
            || self.withdrawal_chains.len() > 256
            || self.withdrawal_chains.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || (self.state == GuardianAccountState::Halted) != self.halt_reason.is_some() { return Err(GuardianSignError::DatabaseUnavailable); }
        validate_hash(self.last_checkpoint_hash)?;
        validate_hash(self.account_public_key)?;
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
    if request.network_magic != account.network_magic || request.user_id != account.user_id || request.decode_trace()?.meta.public_key != account.account_public_key { return Err(GuardianSignError::AccountIdentityConflict); }
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

/// One verified deposit leaf, shared by the live L1 verifier and the offline
/// bridge reset so the two cannot drift. The leaf joins the trailing partial
/// page (cleared on every 32nd leaf) and the frontier; the returned hash is the
/// root after the append.
pub fn accumulate_deposit_leaf(frontier: &mut [Hash4; 32], occupied_partial_page_hashes: &mut Vec<Hash4>, index: u32, leaf: Hash4) -> Hash4 {
    occupied_partial_page_hashes.push(leaf);
    if (index + 1) % 32 == 0 { occupied_partial_page_hashes.clear(); }
    append_merkle_leaf(frontier, index, leaf)
}

pub fn withdrawal_tree_leaf(record: &WithdrawalBurnRecord) -> Hash4 {
    let mut fields = [GoldilocksField::ZERO; 35];
    fields[0] = GoldilocksField::from_canonical_u32(record.sender_user_id);
    for (target, words) in fields[1..34].chunks_exact_mut(8).zip([&record.recipient, &record.token, &record.amount, &record.nonce]) {
        for (target, word) in target.iter_mut().zip(words) { *target = GoldilocksField::from_canonical_u32(*word); }
    }
    fields[33] = GoldilocksField::from_canonical_u8(record.destination_chain_index);
    fields[34] = GoldilocksField::from_canonical_u32(record.token_contract_id);
    PsyHasher::q_hash_many(&fields)
}


impl GuardianSessionRecord {
    pub fn validate(&self, config: &GuardianConfig) -> Result<GuardianSignRequest, GuardianSignError> {
        let request = self.request_json.decode()?;
        request.validate_authorization(config)?;
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
        decode_hex(&self.endcap_proof_hex)
    }
}
impl GuardianSessionsResponse {
    pub fn to_bytes(&self) -> Result<Vec<u8>, GuardianSignError> {
        let bytes = serde_json::to_vec(self).map_err(|_| GuardianSignError::MalformedRequest)?;
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
        let mut input = RequestBytes { remaining: bytes };
        if input.take::<8>()? != *b"PSYGS002" { return Err(GuardianSignError::MalformedRequest); }
        let schema_version = input.u32()?;
        let network_magic = input.u64()?;
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
        let request = Self { schema_version, network_magic, user_id, session_nonce, operation, trace_json, deposit_anchors, withdrawal_records };
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
    fn burn_amount_accepts_full_uint256_and_rejects_only_zero() {
        // The withdrawal amount is a full uint256: the field order is not a
        // bound, and amounts above 2^64 or with high words set are valid.
        assert!(burn(GOLDILOCKS_MODULUS - 1).validate_amount().is_ok());
        assert!(burn(GOLDILOCKS_MODULUS).validate_amount().is_ok());
        assert!(burn(u64::MAX).validate_amount().is_ok());
        let mut record = burn(1); record.amount[0] = 1; assert!(record.validate_amount().is_ok());
        assert!(burn(0).validate_amount().is_err());
        assert_eq!(record.token_address().unwrap().0, [0; 20]);
        record.token[2] = 1; assert!(record.token_address().is_err());
        record.recipient = [0; 8]; assert_eq!(record.recipient_address().unwrap().0, [0; 20]);
    }

    #[test]
    fn raw_high_bits_and_zero_recipient_are_not_request_rejections() {
        let mut request = codec_request_fixture();
        request.operation = GuardianOperation::Bridge;
        let mut first = burn(1);
        first.token[0] = 1;
        first.recipient = [0; 8];
        let mut second = burn(1);
        second.nonce[7] = 8;
        second.recipient[0] = 1;
        request.withdrawal_records = vec![first.clone(), second.clone(), first];
        assert!(request.validate().is_ok());
        assert_eq!(request.withdrawal_records[0].token[0], 1);
        assert_eq!(request.withdrawal_records[0].recipient, [0; 8]);
        assert_eq!(request.withdrawal_records[1].recipient[0], 1);
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
        meta: TraceMeta { network_magic: 90101, user_id: BRIDGE_USER_ID, public_key: codec_config_fixture(90101).account_public_key().unwrap() },
        anchor: SessionAnchor { start_checkpoint_id: 0, checkpoint_leaf: Default::default(), global_state_roots: Default::default(), ups_step_circuit_whitelist_root: Hash4::ZERO },
        ups_start_witness: UpsStartWitness { ups_header: Default::default(), state_roots: Default::default(), checkpoint_tree_proof: Default::default(), user_tree_proof: Default::default(), user_registration_tree_proof: None, proof: None },
        contract_codes: vec![], steps: vec![],
        finalization: TxFinalization { submit_end_cap_input: Default::default(), nonce: GoldilocksField(1), tx_hash: Hash4::ZERO, software_defined_call: Default::default(), sig_hash: Hash4::ZERO },
    };
    let generated = GeneratedTxTraceJson::from_trace(&trace, serde_json::to_value(ContractCallData::new(vec![])).unwrap()).unwrap();
    GuardianSignRequest { schema_version: 3, network_magic: 90101, user_id: BRIDGE_USER_ID, session_nonce: 1, operation: GuardianOperation::Bootstrap, trace_json: JsonText::from_value(&generated).unwrap(), deposit_anchors: vec![], withdrawal_records: vec![] }
}

#[cfg(test)]
mod request_tests {
    use super::*;

    #[test]
    fn request_roundtrip_has_exact_header_widths_and_rejects_noncanonical_bytes() {
        let request = codec_request_fixture();
        let bytes = request.canonical_bytes().unwrap();
        assert_eq!(&bytes[..8], b"PSYGS002");
        assert_eq!(&bytes[8..12], &3u32.to_le_bytes());
        assert_eq!(&bytes[12..20], &90101u64.to_le_bytes());
        assert_eq!(&bytes[20..28], &524288u64.to_le_bytes());
        assert_eq!(&bytes[28..36], &1u64.to_le_bytes());
        assert_eq!(bytes[36], 1);
        assert_eq!(&bytes[37..45], &(request.trace_json.as_str().len() as u64).to_le_bytes());
        assert_eq!(&bytes[bytes.len() - 16..], &[0; 16]);
        assert_eq!(GuardianSignRequest::from_canonical_bytes(&bytes).unwrap().canonical_bytes().unwrap(), bytes);
        for length in [0, 7, 36, 44, bytes.len() - 1] { assert!(GuardianSignRequest::from_canonical_bytes(&bytes[..length]).is_err()); }
        let mut invalid = bytes.clone(); invalid.push(0); assert!(GuardianSignRequest::from_canonical_bytes(&invalid).is_err());
        let mut invalid = bytes.clone(); invalid[36] = 3; assert!(GuardianSignRequest::from_canonical_bytes(&invalid).is_err());
        let mut invalid = bytes; invalid[37..45].copy_from_slice(&u64::MAX.to_le_bytes()); assert!(GuardianSignRequest::from_canonical_bytes(&invalid).is_err());
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
    pub fn validate(&self, config: &GuardianConfig) -> Result<(), GuardianSignError> {
        let request = self.record.validate(config)?;
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
    fn request_vector_bounds_keep_indexed_duplicates() {
        let mut request = codec_request_fixture(); request.operation = GuardianOperation::Bridge;
        request.deposit_anchors = (0..=256).map(|i| DepositAnchor { chain_index: i as u8, block_number: 1, block_hash: Hex([1; 32]), old_count: 0, new_count: 1 }).collect();
        assert_eq!(request.validate().unwrap_err(), GuardianSignError::MalformedRequest);
        request.deposit_anchors.clear();
        let burn = WithdrawalBurnRecord { sender_user_id: 1, token_contract_id: 4, destination_chain_index: 0, token: [0; 8], amount: [0, 0, 0, 0, 0, 0, 0, 1], recipient: [0, 0, 0, 0, 0, 0, 0, 1], nonce: [0; 8] };
        request.withdrawal_records = vec![burn.clone(); 1025];
        assert_eq!(request.validate().unwrap_err(), GuardianSignError::MalformedRequest);
        let mut later = burn.clone(); later.sender_user_id = 2; later.destination_chain_index = 1;
        let mut earlier = burn.clone(); earlier.destination_chain_index = 0; earlier.nonce[7] = 1;
        request.withdrawal_records = vec![later, burn.clone(), earlier, burn];
        assert!(request.validate().is_ok());
        assert_eq!(request.withdrawal_records.iter().map(|record| (record.destination_chain_index, record.sender_user_id, record.nonce[7])).collect::<Vec<_>>(), vec![(1, 2, 0), (0, 1, 0), (0, 1, 1), (0, 1, 0)]);
    }

    #[test]
    fn digest_is_standard_sha256_without_extra_domain() {
        assert_eq!(hex::encode(sha256(b"abc").0), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn proof_hex_has_no_size_ceiling_and_page_counts_stay_semantic() {
        assert_eq!(decode_hex("0x0001").unwrap(), [0, 1]);
        let long_proof = format!("0x{}", "ab".repeat(4096));
        assert_eq!(decode_hex(&long_proof).unwrap().len(), 4096);
        let page = GuardianSessionsResponse { sessions: vec![], next_after_nonce: 7, has_more: false };
        assert!(page.validate_page(7, 1).is_ok());
        assert!(page.validate_page(6, 1).is_err());
        assert!(page.validate_page(7, 0).is_err());
        assert!(page.validate_page(7, 65).is_err());
    }
}

#[cfg(test)]
pub(crate) fn codec_config_fixture(magic: u64) -> GuardianConfig {
    let network = serde_json::from_value(serde_json::json!({
        "magic": format!("0x{magic:x}"), "users_per_realm": 1, "global_user_tree_height": 1, "realm_user_tree_height": 1, "group_realm_height": 1,
        "guardian_initial_member_hashes": [Hash4::from_values(1, 0, 0, 0), Hash4::from_values(2, 0, 0, 0), Hash4::from_values(3, 0, 0, 0)],
        "realm_configs": [], "p2p": {"checkpoints_per_epoch": 1}, "coordinator_configs": [{"id": 0, "rpc_url": ["http://coordinator/"]}],
        "prove_proxy_url": [], "faucet_rpc_url": [], "nostr_relay_url": "", "native_currency": "", "native_currency_decimal": 0,
        "native_currency_name": "", "fees": {"register_user_fee": 0, "deploy_contract_fee": 0, "guta_fee": 0, "da_fee": 0},
        "guardian_configs": [], "guardian_history": {"listen_address": "127.0.0.1:15450"}
    })).unwrap();
    let chain = |index: u8, id: u64, bridge: u8| ChainEndpoint {
        chain_index: index, chain_id: U256::from(id), bridge: Hex([bridge; 20]), deployment_block: 0, rpc_url: format!("https://chain{index}.example/rpc"),
    };
    GuardianConfig { network, guardian_root: PathBuf::new(), endpoints: std::array::from_fn(|_| "http://127.0.0.1/".into()), history_url: "http://127.0.0.1/".into(), l1_chains: vec![chain(0, 7, 0x11), chain(1, 8, 0x22)] }
}

#[cfg(test)]
mod cutover_tests {
    use super::*;

    #[test]
    fn old_request_schema_and_removed_fields_are_rejected() {
        let request = codec_request_fixture();
        let mut bytes = request.canonical_bytes().unwrap();
        bytes[..8].copy_from_slice(b"PSYGS001");
        assert!(GuardianSignRequest::from_canonical_bytes(&bytes).is_err());
        let mut old = request.clone(); old.schema_version = 1;
        assert!(old.validate().is_err());
        for field in ["authorization_sha256", "genesis_hash"] {
            let mut json = serde_json::to_value(&request).unwrap();
            json[field] = serde_json::to_value(Hex([1; 32])).unwrap();
            assert!(GuardianSignRequest::parse(&serde_json::to_vec(&json).unwrap()).is_err());
        }
    }

    #[test]
    fn initial_account_preserves_order_and_rejects_invalid_members() {
        let mut config = codec_config_fixture(90101);
        let account = config.initial_account().unwrap();
        assert_eq!(account.contract_id, MULTISIG_POLICY_CONTRACT_ID);
        assert_eq!(account.initial_policy.member_hashes[..3], config.network.guardian_initial_member_hashes.unwrap());
        assert_eq!(account.initial_policy.member_hashes[3..], [Hash4::ZERO; 5]);
        let key = config.account_public_key().unwrap();
        config.network.guardian_initial_member_hashes.as_mut().unwrap().swap(0, 1);
        assert_ne!(config.account_public_key().unwrap(), key);
        config.network.guardian_initial_member_hashes.as_mut().unwrap()[0] = Hash4::ZERO;
        assert!(config.initial_account().is_err());
        config.network.guardian_initial_member_hashes = Some([Hash4::from_values(1, 0, 0, 0); 3]);
        assert!(config.initial_account().is_err());
    }
}

#[cfg(test)]
mod record_codec_tests {
    use super::*;

    #[test]
    fn record_roundtrip_preserves_binary_and_nested_json_exactly() {
        let inner = codec_request_fixture().canonical_bytes().unwrap();
        assert!(inner.windows(8).any(|window| window == b"PSYGS002"));
        let nested = br#"{"trace":{"code":"fn main() {}","note":"a\"b\\c"},"list":[1,null,true]}"#;
        for payload in [inner.as_slice(), nested.as_slice(), b"".as_slice(), &[0, 255, 10, 13]] {
            let frame = encode_record(payload).unwrap();
            assert_eq!(&frame[..8], b"PSYGR001");
            assert_eq!(&frame[8..12], &RECORD_VERSION.to_le_bytes());
            assert_eq!(&frame[12..20], &(payload.len() as u64).to_le_bytes());
            assert_eq!(decode_record(&frame).unwrap(), payload);
        }
        let signed = codec_request_fixture();
        let frame = encode_record(&signed.canonical_bytes().unwrap()).unwrap();
        assert_eq!(GuardianSignRequest::from_canonical_bytes(&decode_record(&frame).unwrap()).unwrap().request_id().unwrap(), signed.request_id().unwrap());
    }
    #[test]
    fn record_roundtrips_a_real_payload_above_the_former_cap() {
        // Deterministic near-incompressible stream: the real former cap plus one byte,
        // not a zero-filled shortcut.
        let former_cap = 128 * 1024 * 1024;
        let mut payload = vec![0u8; former_cap + 1];
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for byte in &mut payload {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *byte = (state >> 33) as u8;
        }
        let frame = encode_record(&payload).unwrap();
        assert_eq!(&frame[..8], b"PSYGR001");
        assert_eq!(&frame[12..20], &((former_cap + 1) as u64).to_le_bytes());
        assert_eq!(decode_record(&frame).unwrap(), payload);
    }

    #[test]
    fn record_rejects_malformed_unsupported_truncated_trailing_and_size_lies() {
        let payload = b"exact-inner";
        let frame = encode_record(payload).unwrap();
        assert!(decode_record(&frame[..RECORD_HEADER_LEN - 1]).is_err());
        let mut bad = frame.clone(); bad[..8].copy_from_slice(b"PSYGR000");
        assert!(decode_record(&bad).is_err());
        let mut bad = frame.clone(); bad[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert!(decode_record(&bad).is_err());
        assert!(decode_record(&frame[..frame.len() - 1]).is_err());
        assert!(decode_record(&frame[..RECORD_HEADER_LEN]).is_err());
        let mut bad = frame.clone(); bad.truncate(RECORD_HEADER_LEN + 4);
        assert!(decode_record(&bad).is_err());
        let mut bad = frame.clone(); bad[RECORD_HEADER_LEN..RECORD_HEADER_LEN + 4].copy_from_slice(&0x184D2A50u32.to_le_bytes());
        assert!(decode_record(&bad).is_err());
        let mut bad = frame.clone(); bad.extend_from_slice(&frame[RECORD_HEADER_LEN..]);
        assert!(decode_record(&bad).is_err());
        let mut bad = frame.clone(); bad.extend_from_slice(&[0]);
        assert!(decode_record(&bad).is_err());
        let mut bad = frame.clone(); bad[12..20].copy_from_slice(&(payload.len() as u64 + 1).to_le_bytes());
        assert!(decode_record(&bad).is_err());
        let mut bad = frame.clone(); bad[12..20].copy_from_slice(&(payload.len() as u64 - 1).to_le_bytes());
        assert!(decode_record(&bad).is_err());
        let mut bad = frame.clone(); bad[12..20].copy_from_slice(&((64 * 1024 * 1024) as u64).to_le_bytes());
        assert!(decode_record(&bad).is_err());
        let mut bad = frame; bad[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode_record(&bad).is_err());
    }

    #[test]
    fn record_rejects_a_decompression_bomb_before_expanding_it() {
        let mut bomb = encode_record(&vec![0u8; 64 * 1024]).unwrap();
        assert!(bomb.len() < 1024);
        bomb[12..20].copy_from_slice(&1024u64.to_le_bytes());
        assert!(decode_record(&bomb).is_err());
    }
}

#[cfg(test)]
mod schema_cutover_tests {
    use super::*;
    use psy_client_common::data::alt::AltVerifierOnlyCircuitData;
    use psy_crypto::hash::merkle::core::DeltaMerkleProofCore;
    use psy_prover::trace::{CfcProofRecord, CfcStateDelta, CfcStep, ExternalProofStep, SessionAnchor, TxFinalization, TraceContractCode, TraceMeta, TraceSignCircuitSource, TraceStepId, UpsStartProofRecord, UpsStartWitness, ZkSignStep};
    use psy_vm::vm::cfc_input::DapenContractFunctionCircuitInput;

    /// The old serializer wrote byte fields as JSON digit arrays; the codec now writes
    /// padded standard base64. Tests build the old shape from the typed bytes directly,
    /// never by decoding the new text, so the rewrite stays independently checked.
    fn digit_array(bytes: &[u8]) -> Value {
        Value::Array(bytes.iter().map(|byte| Value::from(*byte)).collect())
    }

    fn state_delta() -> CfcStateDelta {
        CfcStateDelta {
            cfc_transaction_input_context: Default::default(),
            user_contract_tree_update_proof: DeltaMerkleProofCore { old_root: Hash4::ZERO, old_value: Hash4::ZERO, new_root: Hash4::ZERO, new_value: Hash4::ZERO, index: 0, siblings: Vec::new() },
            deferred_tx_debt_pivot_proof: Default::default(),
            inline_tx_debt_pivot_proof: Default::default(),
        }
    }

    fn alt_verifier_data() -> AltVerifierOnlyCircuitData<GoldilocksField> {
        AltVerifierOnlyCircuitData { constants_sigmas_cap: Vec::new(), circuit_digest: Hash4::ZERO }
    }

    fn cfc_step(proof: Option<CfcProofRecord>) -> TraceStep {
        TraceStep::Standard(CfcStep {
            id: TraceStepId(0), parent: None, inlined: Vec::new(), deferred: Vec::new(),
            contract_id: 5, fn_id: 1, method_id: 2, method_name: "set_value".to_owned(),
            cfc_fingerprint: Hash4::ZERO, ups_fingerprint: Hash4::ZERO,
            proof_tree_start_root: Hash4::ZERO, proof_tree_end_root: Hash4::ZERO,
            cfc_witness: DapenContractFunctionCircuitInput::default(),
            state_delta: state_delta(),
            cfc_inclusion_proof: Default::default(),
            end_header: Default::default(),
            debt_removal_proof: None,
            proof,
        })
    }

    fn external_step(proof: &[u8]) -> TraceStep {
        TraceStep::ExternalProof(ExternalProofStep {
            fingerprint: Hash4::ZERO, proof_tree_start_root: Hash4::ZERO, proof_tree_end_root: Hash4::ZERO,
            proof: proof.to_vec(),
            verifier_data_alt: alt_verifier_data(),
            siblings: Vec::new(),
        })
    }

    fn zk_sign_step() -> TraceStep {
        TraceStep::ZkSign(ZkSignStep {
            fingerprint: Hash4::ZERO, proof_tree_start_root: Hash4::ZERO, proof_tree_end_root: Hash4::ZERO,
            sign_circuit_source: TraceSignCircuitSource::SdKeyDpn { function_def: vec![7, 8, 9], config: psy_client_data::dpn::sd_key::SDKeyConfig::default() },
            sign_witness: vec![1, 2, 3, 4],
            public_key_param: Hash4::ZERO,
            sign_verifier_data_alt: alt_verifier_data(),
        })
    }

    fn trace_with(ups_proof: Option<Vec<u8>>, contract_codes: Vec<TraceContractCode>, steps: Vec<TraceStep>) -> TxTrace {
        TxTrace {
            meta: TraceMeta { network_magic: 90101, user_id: BRIDGE_USER_ID, public_key: codec_config_fixture(90101).account_public_key().unwrap() },
            anchor: SessionAnchor { start_checkpoint_id: 0, checkpoint_leaf: Default::default(), global_state_roots: Default::default(), ups_step_circuit_whitelist_root: Hash4::ZERO },
            ups_start_witness: UpsStartWitness {
                ups_header: Default::default(), state_roots: Default::default(),
                checkpoint_tree_proof: Default::default(), user_tree_proof: Default::default(),
                user_registration_tree_proof: None,
                proof: ups_proof.map(|proof| UpsStartProofRecord { proof }),
            },
            contract_codes, steps,
            finalization: TxFinalization { submit_end_cap_input: Default::default(), nonce: GoldilocksField(1), tx_hash: Hash4::ZERO, software_defined_call: Default::default(), sig_hash: Hash4::ZERO },
        }
    }

    fn call_data() -> Value { serde_json::to_value(ContractCallData::new(vec![])).unwrap() }

    fn request(schema_version: u32, generated: &GeneratedTxTraceJson) -> GuardianSignRequest {
        GuardianSignRequest {
            schema_version, network_magic: 90101, user_id: BRIDGE_USER_ID, session_nonce: 1,
            operation: GuardianOperation::Bootstrap, trace_json: JsonText::from_value(generated).unwrap(),
            deposit_anchors: vec![], withdrawal_records: vec![],
        }
    }

    /// Mimics the old serializer: non-empty byte fields become digit arrays, empty ones
    /// stay omitted, keyed off the typed trace instead of decoding the new base64 text.
    fn schema2_payload(trace: &TxTrace, generated: &GeneratedTxTraceJson) -> String {
        let mut payload: Value = serde_json::from_str(&generated.trace.payload).unwrap();
        if let Some(record) = trace.ups_start_witness.proof.as_ref() {
            if !record.proof.is_empty() { payload["ups_start_witness"]["proof"]["proof"] = digit_array(&record.proof); }
        }
        if let Some(code) = trace.contract_codes.first() {
            if !code.code.is_empty() { payload["contract_codes"][0]["code"] = digit_array(&code.code); }
        }
        for (index, step) in trace.steps.iter().enumerate() {
            match step {
                TraceStep::Standard(_) | TraceStep::BurnFee(_) | TraceStep::Inlined(_) | TraceStep::Deferred(_) => {
                    let record = step.as_cfc().unwrap().proof.as_ref();
                    if let Some(record) = record {
                        if !record.cfc_proof.is_empty() { payload["steps"][index]["proof"]["cfc_proof"] = digit_array(&record.cfc_proof); }
                        if !record.ups_proof.is_empty() { payload["steps"][index]["proof"]["ups_proof"] = digit_array(&record.ups_proof); }
                    }
                }
                TraceStep::ExternalProof(external) => {
                    if !external.proof.is_empty() { payload["steps"][index]["proof"] = digit_array(&external.proof); }
                }
                TraceStep::ZkSign(sign) => {
                    if !sign.sign_witness.is_empty() { payload["steps"][index]["sign_witness"] = digit_array(&sign.sign_witness); }
                    if let TraceSignCircuitSource::SdKeyDpn { function_def, .. } = &sign.sign_circuit_source {
                        if !function_def.is_empty() { payload["steps"][index]["sign_circuit_source"]["function_def"] = digit_array(function_def); }
                    }
                }
            }
        }
        serde_json::to_string(&payload).unwrap()
    }

    #[test]
    fn schema2_request_blob_keeps_identity_and_walks_the_old_trace() {
        let trace = trace_with(None, vec![TraceContractCode { contract_id: 5, code: vec![1, 2, 3, 255] }], vec![cfc_step(None), zk_sign_step()]);
        let generated = GeneratedTxTraceJson::from_trace(&trace, call_data()).unwrap();
        let schema3 = request(3, &generated);
        let schema3_blob = schema3.canonical_bytes().unwrap();
        assert_eq!(&schema3_blob[8..12], &3u32.to_le_bytes());
        let payload: Value = serde_json::from_str(&generated.trace.payload).unwrap();
        assert!(payload["contract_codes"][0]["code"].is_string());
        assert!(payload["steps"][1]["sign_witness"].is_string());
        assert!(payload["steps"][1]["sign_circuit_source"]["function_def"].is_array());
        let old = GuardianSignRequest { schema_version: 2, ..request(3, &schema2_generated(&trace)) };
        let json = serde_json::to_vec(&old).unwrap();
        let blob = old.canonical_bytes().unwrap();
        assert_eq!(&blob[..8], b"PSYGS002");
        assert_eq!(&blob[8..12], &2u32.to_le_bytes());
        let decoded = GuardianSignRequest::from_canonical_bytes(&blob).unwrap();
        assert_eq!(decoded.schema_version, 2);
        assert_eq!(decoded.canonical_bytes().unwrap(), blob);
        assert_eq!(decoded.request_id().unwrap(), sha256(&blob));
        assert_ne!(decoded.request_id().unwrap(), schema3.request_id().unwrap());
        assert!(traces_equal(&decoded.decode_trace().unwrap(), &trace).unwrap());
        assert!(GuardianSignRequest::parse(&json).is_err());
        assert!(GuardianSignRequest::parse_retained(&json).is_ok());
    }

    fn schema2_generated(trace: &TxTrace) -> GeneratedTxTraceJson {
        let generated = GeneratedTxTraceJson::from_trace(trace, call_data()).unwrap();
        let mut old = generated.clone();
        old.trace.payload = schema2_payload(trace, &generated);
        old
    }

    #[test]
    fn seven_byte_paths_accept_digit_arrays_and_base64_strings() {
        let trace = trace_with(Some(vec![1]), vec![TraceContractCode { contract_id: 5, code: vec![10, 20, 30] }],
            vec![cfc_step(Some(CfcProofRecord { cfc_proof: vec![40, 50], ups_proof: vec![60] })), external_step(&[70, 80]), zk_sign_step()]);
        let generated = GeneratedTxTraceJson::from_trace(&trace, call_data()).unwrap();
        let direct: TxTrace = parse_canonical_json(generated.trace.payload.as_bytes()).unwrap();
        assert!(traces_equal(&direct, &trace).unwrap());
        let rewritten = rewrite_schema2_trace_payload(&schema2_payload(&trace, &generated)).unwrap();
        let walked: TxTrace = parse_canonical_json(rewritten.as_bytes()).unwrap();
        assert!(traces_equal(&walked, &trace).unwrap());
        assert_eq!(walked.ups_start_witness.proof.unwrap().proof, vec![1]);
        assert_eq!(walked.contract_codes[0].code, vec![10, 20, 30]);
        let TraceStep::Standard(step) = &walked.steps[0] else { unreachable!() };
        assert_eq!(step.proof.as_ref().unwrap().cfc_proof, vec![40, 50]);
        assert_eq!(step.proof.as_ref().unwrap().ups_proof, vec![60]);
        let TraceStep::ExternalProof(step) = &walked.steps[1] else { unreachable!() };
        assert_eq!(step.proof, vec![70, 80]);
        let TraceStep::ZkSign(step) = &walked.steps[2] else { unreachable!() };
        assert_eq!(step.sign_witness, vec![1, 2, 3, 4]);
        assert!(matches!(&step.sign_circuit_source, TraceSignCircuitSource::SdKeyDpn { function_def, .. } if function_def == &vec![7, 8, 9]));
    }

    #[test]
    fn listed_paths_reject_wrong_types_while_unrelated_arrays_pass() {
        let trace = trace_with(None, vec![TraceContractCode { contract_id: 5, code: vec![1, 2] }], vec![cfc_step(None), zk_sign_step()]);
        let payload: Value = serde_json::from_str(&schema2_generated(&trace).trace.payload).unwrap();
        for bad in [Value::String("aa".to_owned()), serde_json::json!([256]), serde_json::json!([-1]), serde_json::json!([1.5]), serde_json::json!({}), Value::Null] {
            let mut payload = payload.clone();
            payload["steps"][1]["sign_witness"] = bad;
            assert!(rewrite_schema2_trace_payload(&serde_json::to_string(&payload).unwrap()).is_err());
        }
        {
            let mut payload = payload.clone();
            payload["contract_codes"][0]["code"] = Value::String("aa".to_owned());
            assert!(rewrite_schema2_trace_payload(&serde_json::to_string(&payload).unwrap()).is_err());
        }
        // Off the seven listed paths a numeric array above 255 stays an array and stays valid.
        let mut payload = payload.clone();
        payload["steps"][0]["inlined"] = serde_json::json!([400]);
        let rewritten = rewrite_schema2_trace_payload(&serde_json::to_string(&payload).unwrap()).unwrap();
        let walked: TxTrace = parse_canonical_json(rewritten.as_bytes()).unwrap();
        let TraceStep::Standard(step) = &walked.steps[0] else { unreachable!() };
        assert_eq!(step.inlined, vec![TraceStepId(400)]);
    }

    #[test]
    fn empty_digit_array_at_a_listed_path_fails_the_canonical_check() {
        let trace = trace_with(None, vec![TraceContractCode { contract_id: 5, code: vec![1] }], vec![zk_sign_step()]);
        let generated = schema2_generated(&trace);
        let mut payload: Value = serde_json::from_str(&generated.trace.payload).unwrap();
        payload["contract_codes"][0]["code"] = digit_array(&[]);
        let rewritten = rewrite_schema2_trace_payload(&serde_json::to_string(&payload).unwrap()).unwrap();
        assert!(parse_canonical_json::<TxTrace>(rewritten.as_bytes()).is_err());
    }

    #[test]
    fn precomputed_proofs_still_rejected_after_the_schema2_rewrite() {
        for trace in [
            trace_with(Some(vec![1, 2]), vec![], vec![zk_sign_step()]),
            trace_with(None, vec![], vec![cfc_step(Some(CfcProofRecord { cfc_proof: vec![3], ups_proof: vec![4] })), zk_sign_step()]),
            trace_with(None, vec![], vec![external_step(&[5]), zk_sign_step()]),
        ] {
            let old = GuardianSignRequest { schema_version: 2, ..request(3, &schema2_generated(&trace)) };
            assert_eq!(old.validate().unwrap_err(), GuardianSignError::MalformedRequest);
        }
    }
}
