use bincode::Options;
use redb::{Key, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle, TypeName, Value};

use std::{collections::{BTreeMap, BTreeSet}, fs::File, path::{Path, PathBuf}, sync::Arc, time::Duration};

use anyhow::{Context, ensure};
use futures::{stream::FuturesUnordered, StreamExt};
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut};
use psy_crypto::signature::secp256k1::core::PsyCompressedSecp256K1Signature;
use psy_prover::signature::users::multisig_user::validate_policy_signatures;
use psy_vm::ups::multisig::{MultisigPolicy, MultisigSignatures};

use guardian_common::protocol::{self, advance_included_account, validate_changed_deposit_tree_states, DepositTreeState, GuardianAccount, GuardianSession, GuardianSignError, GuardianSignRequest, GuardianSignResponse, GuardianSignErrorResponse, GuardianSessionRecord, GuardianSessionsResponse, HaltReason, JsonText, BRIDGE_USER_ID};
use guardian_common::runtime::{create_db_file, open_db_file};

pub(crate) struct LoadedGuardianConfig {
    pub root: guardian_common::protocol::GuardianConfig,
    pub db: Arc<RelayerDb>,
}

impl LoadedGuardianConfig {
    pub async fn load_network(rpc_config: &Path, guardian_root: &Path, local_documents: &[PathBuf]) -> anyhow::Result<guardian_common::protocol::GuardianConfig> {
        guardian_common::protocol::GuardianConfig::load(rpc_config, guardian_root, local_documents).await.map_err(Into::into)
    }

    pub async fn load(rpc_config: &Path, guardian_root: &Path, local_documents: &[PathBuf]) -> anyhow::Result<Self> {
        let root = Self::load_network(rpc_config, guardian_root, local_documents).await?;
        let db = Arc::new(RelayerDb::open(&root.guardian_root)?);
        Ok(Self { root, db })
    }

    pub fn endpoints(&self) -> &[String; 3] { &self.root.endpoints }


    pub fn config(&self) -> &guardian_common::protocol::GuardianConfig { &self.root }

    pub async fn serve_history(&self) -> anyhow::Result<()> {
        let listen = self.root.network.guardian_history.as_ref().context("guardian history missing")?.listen_address.to_string();
        crate::guardian::service::serve_relayer_history(&listen, self.db.clone()).await.map_err(Into::into)
    }
}

pub(crate) struct GuardianClient {
    http: reqwest::Client,
    endpoints: [url::Url; 3],
}

impl GuardianClient {
    pub fn new(endpoints: &[String; 3]) -> anyhow::Result<Self> {
        let endpoints = endpoints.iter().map(|text| {
            let url = url::Url::parse(text)?;
            ensure!(url.scheme() == "http" && url.host().is_some() && url.username().is_empty() && url.password().is_none() && (url.path() == "/" || url.path().is_empty()) && url.query().is_none() && url.fragment().is_none() && url.port().unwrap_or(80) != 0, "guardian endpoint must be a fixed HTTP origin");
            Ok(url)
        }).collect::<anyhow::Result<Vec<_>>>()?;
        ensure!(endpoints[0] != endpoints[1] && endpoints[0] != endpoints[2] && endpoints[1] != endpoints[2], "guardian origins must be distinct");
        // No total request deadline: the sign POST waits out the guardian's unbounded signing
        // phase. Connection establishment stays transport-bounded; the history GET re-applies
        // its own per-request deadline.
        let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10)).no_gzip().no_brotli().no_deflate().no_zstd().build()?;
        Ok(Self { http, endpoints: endpoints.try_into().map_err(|_| anyhow::anyhow!("three guardian endpoints required"))? })
    }

    pub async fn session_record(&self, after_nonce: u64) -> anyhow::Result<Option<GuardianSessionRecord>> {
        let nonce = after_nonce.checked_add(1).context("history nonce overflow")?;
        let mut selected: Option<GuardianSessionRecord> = None;
        let mut saw_conflict = false;
        for origin in &self.endpoints {
            let mut url = origin.clone();
            url.set_path("/v1/sessions");
            url.query_pairs_mut().append_pair("after_nonce", &after_nonce.to_string()).append_pair("limit", "1");
            // Same whole-request bound the shared client previously applied to this GET.
            let Ok(mut response) = self.http.get(url).timeout(Duration::from_secs(620)).header(reqwest::header::ACCEPT, GUARDIAN_RECORD).send().await else { continue };
            if !response.status().is_success() { continue; }
            let Some(content_type) = response.headers().get(reqwest::header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).map(|value| value.split(';').next().unwrap_or("").trim().to_owned()) else { continue };
            if !content_type.eq_ignore_ascii_case(GUARDIAN_RECORD) && !content_type.eq_ignore_ascii_case("application/json") { continue; }
            let mut body = Vec::new();
            let mut failed = false;
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) => {
                        if body.try_reserve(chunk.len()).is_err() { failed = true; break; }
                        body.extend_from_slice(&chunk);
                    }
                    Ok(None) => break,
                    _ => { failed = true; break; }
                }
            }
            if failed { continue; }
            let json = if content_type.eq_ignore_ascii_case(GUARDIAN_RECORD) {
                let Ok(decoded) = protocol::decode_record(&body) else { continue };
                decoded
            } else { body };
            let Ok(page) = protocol::parse_canonical_json::<GuardianSessionsResponse>(&json) else { continue };
            if page.validate_page(after_nonce, 1).is_err() { continue; }
            let Some(record) = page.sessions.into_iter().next() else { continue };
            let Ok(request) = record.request_json.decode() else { saw_conflict = true; continue };
            if request.session_nonce > nonce { continue; }
            if request.session_nonce != nonce { saw_conflict = true; continue; }
            match &selected {
                Some(saved) if serde_json::to_vec(saved)? != serde_json::to_vec(&record)? => saw_conflict = true,
                Some(_) => {}
                None => selected = Some(record),
            }
        }
        if saw_conflict { anyhow::bail!("authenticated guardian history conflict"); }
        Ok(selected)
    }

    pub async fn collect(&self, request_json: &JsonText<GuardianSignRequest>, policy: &MultisigPolicy, sighash: QHashOut<GoldilocksField>) -> anyhow::Result<MultisigSignatures> {
        let request = request_json.decode()?;
        ensure!(request.operation == protocol::GuardianOperation::Bridge, "policy signatures require explicit local operator approval");
        // Cutover gate: retained schema-2 rows stay readable but are never posted, even to an
        // old guardian. Reject locally before any network I/O; the stored row is untouched.
        ensure!(request.schema_version == 3, "schema 2 signing obligation must be included before upgrading; retained request is unchanged");
        policy.validate()?;
        let message = Hash256::from(sighash);
        let mut pending = FuturesUnordered::new();
        for (guardian, origin) in self.endpoints.iter().enumerate() {
            let url = origin.join("v1/sign-session")?;
            let http = &self.http;
            let bytes = request_json.as_str();
            pending.push(async move { (guardian, request_signature(http, guardian, url, bytes).await) });
        }
        let mut accepted = Vec::with_capacity(3);
        let mut hard: [Option<GuardianSignError>; 3] = [None; 3];
        while let Some((guardian, attempt)) = pending.next().await {
            let attempt = attempt?;
            match attempt {
                SignAttempt::Signed(response) => {
                    let signature = match verify_response(&request, policy, message, &response) {
                        Ok(signature) => signature,
                        Err(_) => {
                            tracing::warn!(guardian, member = response.member_index, verified = false, "guardian sign response failed local verification");
                            continue;
                        }
                    };
                    accepted.push((response.member_index, signature));
                    if let Some(signatures) = select_signatures(&mut accepted, policy, sighash) { return Ok(signatures); }
                }
                SignAttempt::Hard(code) => hard[guardian] = Some(code),
                SignAttempt::Missing => {}
            }
        }
        // Lowest endpoint index, not arrival order. Retryable codes and transport gaps stay
        // SignatureQuorumUnavailable so the daemon keeps retrying only that variant.
        if let Some(code) = hard.into_iter().flatten().next() { return Err(code.into()); }
        Err(GuardianSignError::SignatureQuorumUnavailable.into())
    }
}
fn hard_refusal(code: GuardianSignError) -> bool { code.retry_after_ms() == 0 }

enum SignAttempt {
    Signed(GuardianSignResponse),
    Hard(GuardianSignError),
    Missing,
}

async fn request_signature(http: &reqwest::Client, guardian: usize, url: url::Url, bytes: &str) -> anyhow::Result<SignAttempt> {
    let started = std::time::Instant::now();
    let frame = protocol::encode_record(bytes.as_bytes()).map_err(|error| anyhow::anyhow!(error))?;
    let mut response = match http.post(url).header(reqwest::header::CONTENT_TYPE, GUARDIAN_RECORD).body(frame).send().await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(guardian, is_timeout = error.is_timeout(), is_connect = error.is_connect(), is_body = error.is_body(), is_decode = error.is_decode(), "guardian sign transport failed");
            tracing::debug!(guardian, elapsed_ms = started.elapsed().as_millis() as u64, outcome = "transport", "guardian sign-session endpoint finished");
            return Ok(SignAttempt::Missing);
        }
    };
    let status = response.status();
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.try_reserve(chunk.len()).is_err() {
                    tracing::warn!(guardian, status = status.as_u16(), "guardian response collection failed");
                    tracing::debug!(guardian, elapsed_ms = started.elapsed().as_millis() as u64, outcome = "collect_failed", "guardian sign-session endpoint finished");
                    return Ok(SignAttempt::Missing);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(guardian, is_timeout = error.is_timeout(), is_connect = error.is_connect(), is_body = error.is_body(), is_decode = error.is_decode(), "guardian sign transport failed");
                tracing::debug!(guardian, elapsed_ms = started.elapsed().as_millis() as u64, outcome = "transport", "guardian sign-session endpoint finished");
                return Ok(SignAttempt::Missing);
            }
        }
    }
    if status.is_success() {
        return match protocol::parse_canonical_json::<GuardianSignResponse>(&body) {
            Ok(response) => {
                tracing::debug!(guardian, elapsed_ms = started.elapsed().as_millis() as u64, outcome = "signed", "guardian sign-session endpoint finished");
                Ok(SignAttempt::Signed(response))
            }
            Err(_) => {
                tracing::debug!(guardian, elapsed_ms = started.elapsed().as_millis() as u64, outcome = "unreadable", "guardian sign-session endpoint finished");
                tracing::warn!(guardian, status = status.as_u16(), "guardian sign response unreadable");
                Ok(SignAttempt::Missing)
            }
        };
    }
    match protocol::parse_canonical_json::<GuardianSignErrorResponse>(&body) {
        Ok(error) if hard_refusal(error.code) => {
            tracing::warn!(guardian, code = %error.code, "guardian refused sign request");
            tracing::debug!(guardian, elapsed_ms = started.elapsed().as_millis() as u64, outcome = "hard_refusal", "guardian sign-session endpoint finished");
            Ok(SignAttempt::Hard(error.code))
        }
        Ok(error) => {
            tracing::warn!(guardian, code = %error.code, "guardian sign refusal is retryable");
            tracing::debug!(guardian, elapsed_ms = started.elapsed().as_millis() as u64, outcome = "retryable", "guardian sign-session endpoint finished");
            Ok(SignAttempt::Missing)
        }
        Err(_) => {
            tracing::warn!(guardian, status = status.as_u16(), "guardian sign error response unreadable");
            tracing::debug!(guardian, elapsed_ms = started.elapsed().as_millis() as u64, outcome = "unreadable", "guardian sign-session endpoint finished");
            Ok(SignAttempt::Missing)
        }
    }
}

pub(crate) fn select_signatures(accepted: &mut [(u8, PsyCompressedSecp256K1Signature)], policy: &MultisigPolicy, sighash: QHashOut<GoldilocksField>) -> Option<MultisigSignatures> {
    accepted.sort_by_key(|member| member.0);
    for first in 0..accepted.len() {
        for second in first + 1..accepted.len() {
            let signatures = MultisigSignatures {
                member_indices: vec![accepted[first].0, accepted[second].0],
                signatures: vec![accepted[first].1, accepted[second].1],
            };
            if validate_policy_signatures(&signatures, policy, sighash).is_ok() { return Some(signatures); }
        }
    }
    None
}

pub(crate) fn verify_response(request: &GuardianSignRequest, policy: &MultisigPolicy, message: Hash256, response: &GuardianSignResponse) -> anyhow::Result<PsyCompressedSecp256K1Signature> {
    ensure!(response.request_id == request.request_id()? && response.network_magic == request.network_magic && response.user_id == request.user_id && response.session_nonce == request.session_nonce, "guardian response context mismatch");
    ensure!(response.policy_commitment == policy.commitment()? && response.member_index < 3 && response.message.0 == message.0, "guardian response policy/message mismatch");
    Ok(PsyCompressedSecp256K1Signature { public_key: response.public_key.0, signature: response.signature.0, message })
}

const RELAYER_REQUEST: TableDefinition<u64, &[u8]> = TableDefinition::new("relayer_request");
const GUARDIAN_ACCOUNT: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("guardian_account");
const DEPOSIT_TREE_STATES: TableDefinition<DepositTreeKey, &[u8]> = TableDefinition::new("deposit_tree_states");
const INCLUDED_WITHDRAWAL_BURNS: TableDefinition<WithdrawalBurnKey, u64> = TableDefinition::new("included_withdrawal_burns");
const WITHDRAWAL_NONCE: TableDefinition<NonceKey, u64> = TableDefinition::new("guardian_withdrawal_nonce");
const CHAIN_CLAIMS: TableDefinition<u8, &[u8]> = TableDefinition::new("chain_claims");
const FINALIZATION_BATCH: TableDefinition<(), &[u8]> = TableDefinition::new("finalization_batch");
const WITHDRAWAL_QUARANTINE: TableDefinition<(u8, i64), &[u8]> = TableDefinition::new("withdrawal_quarantine");

/// Why an indexed withdrawal is held out of the append/claim set: the Router
/// mapping for its (token, contract id) pair failed the same dual check the
/// guardians apply at signing time. The check is deterministic, so a marker
/// stays for the life of the journal; a transient L1 failure never writes one.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct WithdrawalQuarantine { pub reason: String, pub quarantined_at_unix: u64 }

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ChainClaims {
    pub pending_claim_withdrawals: BTreeMap<String, crate::bridge::propose_withdrawals::PendingWithdrawal>,
    pub claim_retry: BTreeMap<String, crate::bridge::claim_attempts::ClaimAttempts>,
    pub retired_claim_withdrawals: BTreeMap<String, crate::bridge::claim_attempts::RetiredClaim<crate::bridge::propose_withdrawals::PendingWithdrawal>>,
}

impl Default for ChainClaims {
    fn default() -> Self {
        Self { pending_claim_withdrawals: BTreeMap::new(), claim_retry: BTreeMap::new(), retired_claim_withdrawals: BTreeMap::new() }
    }
}

fn withdrawal_fields(withdrawal: &crate::bridge::propose_withdrawals::PendingWithdrawal) -> (i64, u64, u64, u64, u64, u64, [u32; 8], [u32; 8], [u32; 8], [u32; 8], &str) {
    (withdrawal.event_id, withdrawal.checkpoint_id, withdrawal.user_id, withdrawal.sender_user_id, withdrawal.contract_id, withdrawal.destination_chain_index, withdrawal.token_address, withdrawal.amount, withdrawal.recipient, withdrawal.nonce, withdrawal.leaf_hash.as_str())
}

fn same_keyed<V>(left: &BTreeMap<String, V>, right: &BTreeMap<String, V>, same: impl Fn(&V, &V) -> bool) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|((left_key, left_value), (right_key, right_value))| left_key == right_key && same(left_value, right_value))
}

impl PartialEq for ChainClaims {
    fn eq(&self, other: &Self) -> bool {
        same_keyed(&self.pending_claim_withdrawals, &other.pending_claim_withdrawals, |left, right| withdrawal_fields(left) == withdrawal_fields(right))
            && self.claim_retry == other.claim_retry
            && same_keyed(&self.retired_claim_withdrawals, &other.retired_claim_withdrawals, |left, right| {
                withdrawal_fields(&left.withdrawal) == withdrawal_fields(&right.withdrawal)
                    && left.attempts == right.attempts
                    && left.last_reason == right.last_reason
                    && left.retired_at_unix == right.retired_at_unix
            })
    }
}

impl Eq for ChainClaims {}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FinalizationBatch {
    pub pending_finalization_range: Option<FinalizationRange>,
    pub finalized_chains: BTreeSet<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FinalizationRange {
    pub from_checkpoint: u64,
    pub to_checkpoint: u64,
}

const JOURNAL_SCHEMA: TableDefinition<(), u64> = TableDefinition::new("journal_schema");
const JOURNAL_SCHEMA_VERSION: u64 = 4;
const JOURNAL_SCHEMA_V3: u64 = 3;
const JOURNAL_SCHEMA_V2: u64 = 2;
const GUARDIAN_RECORD: &str = "application/vnd.psy.guardian-record+zstd";
const RELAYER_TABLES: [&str; 9] = ["journal_schema", "chain_claims", "finalization_batch", "guardian_account", "deposit_tree_states", "included_withdrawal_burns", "guardian_withdrawal_nonce", "relayer_request", "withdrawal_quarantine"];
const LEGACY_JOURNAL: &str = "incompatible legacy journal schema; explicit operator-controlled migration is required";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DepositTreeKey(u64, u64, u8);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WithdrawalBurnKey(u64, u64, u32, u32, [u32; 8]);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NonceKey(u64, u64, u8, [u32; 8]);

fn put_u32s(bytes: &mut Vec<u8>, words: &[u32]) { for word in words { bytes.extend_from_slice(&word.to_le_bytes()); } }
fn read_u32s<const N: usize>(bytes: &[u8]) -> [u32; N] { std::array::from_fn(|index| u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap())) }

impl Value for DepositTreeKey {
    type SelfType<'a> = Self; type AsBytes<'a> = [u8; 17];
    fn fixed_width() -> Option<usize> { Some(17) }
    fn from_bytes<'a>(data: &'a [u8]) -> Self where Self: 'a { Self(u64::from_le_bytes(data[..8].try_into().unwrap()), u64::from_le_bytes(data[8..16].try_into().unwrap()), data[16]) }
    fn as_bytes<'a, 'b: 'a>(value: &'a Self) -> [u8; 17] where Self: 'a, Self: 'b { let mut bytes = [0; 17]; bytes[..8].copy_from_slice(&value.0.to_le_bytes()); bytes[8..16].copy_from_slice(&value.1.to_le_bytes()); bytes[16] = value.2; bytes }
    fn type_name() -> TypeName { TypeName::new("psy_relayer_cli::DepositTreeKey") }
}
impl Key for DepositTreeKey { fn compare(a: &[u8], b: &[u8]) -> std::cmp::Ordering { a.cmp(b) } }
impl Value for WithdrawalBurnKey {
    type SelfType<'a> = Self; type AsBytes<'a> = Vec<u8>;
    fn fixed_width() -> Option<usize> { Some(56) }
    fn from_bytes<'a>(data: &'a [u8]) -> Self where Self: 'a { Self(u64::from_le_bytes(data[..8].try_into().unwrap()), u64::from_le_bytes(data[8..16].try_into().unwrap()), u32::from_le_bytes(data[16..20].try_into().unwrap()), u32::from_le_bytes(data[20..24].try_into().unwrap()), read_u32s(&data[24..56])) }
    fn as_bytes<'a, 'b: 'a>(value: &'a Self) -> Vec<u8> where Self: 'a, Self: 'b { let mut bytes = Vec::with_capacity(56); bytes.extend_from_slice(&value.0.to_le_bytes()); bytes.extend_from_slice(&value.1.to_le_bytes()); bytes.extend_from_slice(&value.2.to_le_bytes()); bytes.extend_from_slice(&value.3.to_le_bytes()); put_u32s(&mut bytes, &value.4); bytes }
    fn type_name() -> TypeName { TypeName::new("psy_relayer_cli::WithdrawalBurnKey") }
}
impl Key for WithdrawalBurnKey { fn compare(a: &[u8], b: &[u8]) -> std::cmp::Ordering { a.cmp(b) } }
impl Value for NonceKey {
    type SelfType<'a> = Self; type AsBytes<'a> = Vec<u8>;
    fn fixed_width() -> Option<usize> { Some(49) }
    fn from_bytes<'a>(data: &'a [u8]) -> Self where Self: 'a { Self(u64::from_le_bytes(data[..8].try_into().unwrap()), u64::from_le_bytes(data[8..16].try_into().unwrap()), data[16], read_u32s(&data[17..49])) }
    fn as_bytes<'a, 'b: 'a>(value: &'a Self) -> Vec<u8> where Self: 'a, Self: 'b { let mut bytes = Vec::with_capacity(49); bytes.extend_from_slice(&value.0.to_le_bytes()); bytes.extend_from_slice(&value.1.to_le_bytes()); bytes.push(value.2); put_u32s(&mut bytes, &value.3); bytes }
    fn type_name() -> TypeName { TypeName::new("psy_relayer_cli::NonceKey") }
}
impl Key for NonceKey { fn compare(a: &[u8], b: &[u8]) -> std::cmp::Ordering { a.cmp(b) } }

fn bincode_codec() -> impl bincode::Options { bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes() }
fn encode_canonical<T: serde::Serialize>(value: &T) -> anyhow::Result<Vec<u8>> { Ok(bincode_codec().serialize(value)?) }
fn decode_canonical<T: serde::de::DeserializeOwned + serde::Serialize>(bytes: &[u8]) -> anyhow::Result<T> {
    let value: T = bincode_codec().deserialize(bytes)?;
    ensure!(bincode_codec().serialize(&value)?.as_slice() == bytes, "durable row is not canonical");
    Ok(value)
}

/// Durable JSON uses serde's struct field order and ordered map/set iteration.
/// Decoding must reproduce these exact bytes, including nested fields and defaults;
/// converting through `Value` would instead reorder object keys independently.
fn encode_progress<T: serde::Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

fn decode_progress<T: serde::de::DeserializeOwned + serde::Serialize>(bytes: &[u8]) -> anyhow::Result<T> {
    let value: T = serde_json::from_slice(bytes).context("daemon progress row rejected")?;
    ensure!(encode_progress(&value)? == bytes, "daemon progress row is not canonical");
    Ok(value)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
enum Request {
    Request { request: String, deposit_tree_states: Vec<DepositTreeState> },
    Signed { request: String, deposit_tree_states: Vec<DepositTreeState>, signatures: String },
    Proved { request: String, deposit_tree_states: Vec<DepositTreeState>, signatures: String, endcap: Vec<u8> },
    Included { record: GuardianSessionRecord },
}

impl Request {
    fn request_text(&self) -> &str {
        match self {
            Self::Request { request, .. } | Self::Signed { request, .. } | Self::Proved { request, .. } => request,
            Self::Included { record, .. } => record.request_json.as_str(),
        }
    }
    fn account_key(&self) -> anyhow::Result<protocol::Hash4> {
        let request = GuardianSignRequest::parse_retained(self.request_text().as_bytes()).map_err(|error| anyhow::anyhow!(error))?;
        Ok(request.decode_trace()?.meta.public_key)
    }
    fn request(&self) -> anyhow::Result<JsonText<GuardianSignRequest>> {
        JsonText::parse(self.request_text().to_owned()).map_err(|error| anyhow::anyhow!(error))
    }
    fn deposit_tree_states(&self) -> &[DepositTreeState] {
        match self {
            Self::Request { deposit_tree_states, .. } | Self::Signed { deposit_tree_states, .. } | Self::Proved { deposit_tree_states, .. } => deposit_tree_states,
            Self::Included { .. } => &[],
        }
    }
    fn signatures_text(&self) -> Option<&str> {
        match self {
            Self::Request { .. } => None,
            Self::Signed { signatures, .. } | Self::Proved { signatures, .. } => Some(signatures),
            Self::Included { record, .. } => Some(record.signatures_json.as_str()),
        }
    }
}

#[derive(Clone)]
pub(crate) struct RelayerDb { db: Arc<redb::Database> }

impl RelayerDb {
    /// Opens one request database. A missing file is created once; a pre-existing zero-length file is rejected.
    /// The held database is the process lock. The root is walked with `O_NOFOLLOW` and owner/mode checks.
    pub fn open(guardian_root: &Path) -> anyhow::Result<Self> {
        let relative = Path::new("db/relayer.redb");
        let (file, parent, created) = match open_db_file(guardian_root, relative) {
            Ok(file) => (file, None, false),
            Err(_) => {
                let (file, parent) = create_db_file(guardian_root, relative)?;
                (file, Some(parent), true)
            }
        };
        if !created && file.metadata()?.len() == 0 { anyhow::bail!("relayer database is empty"); }
        let db = Self::open_file(file)?;
        if let Some(parent) = parent { parent.sync_all()?; }
        Ok(db)
    }

    /// Validates one already-open database handle. Callers that did not use `open` must have applied the same protections.
    fn open_file(file: File) -> anyhow::Result<Self> {
        let db = redb::Database::builder().create_file(file).context("relayer database open failed")?;
        let names = {
            let tx = db.begin_read()?;
            ensure!(tx.list_multimap_tables()?.next().is_none(), "relayer database contains a multimap table");
            let names = tx.list_tables()?.map(|table| table.name().to_owned()).collect::<std::collections::BTreeSet<_>>();
            names
        };
        if names.is_empty() {
            let tx = db.begin_write()?;
            tx.open_table(JOURNAL_SCHEMA)?.insert((), JOURNAL_SCHEMA_VERSION)?;
            tx.open_table(RELAYER_REQUEST)?;
            tx.open_table(GUARDIAN_ACCOUNT)?;
            tx.open_table(DEPOSIT_TREE_STATES)?;
            tx.open_table(INCLUDED_WITHDRAWAL_BURNS)?;
            tx.open_table(WITHDRAWAL_NONCE)?;
            tx.open_table(CHAIN_CLAIMS)?;
            tx.open_table(FINALIZATION_BATCH)?;
            tx.open_table(WITHDRAWAL_QUARANTINE)?;
            tx.commit()?;
        } else {
            ensure!(names == RELAYER_TABLES.into_iter().map(str::to_owned).collect::<std::collections::BTreeSet<String>>(), "{LEGACY_JOURNAL}");
            let tx = db.begin_read()?;
            let schema = tx.open_table(JOURNAL_SCHEMA)?;
            ensure!(schema.get(())?.map(|row| row.value()) == Some(JOURNAL_SCHEMA_VERSION) && schema.len()? == 1, "{LEGACY_JOURNAL}");
        }
        Ok(Self { db: Arc::new(db) })
    }

    fn current_identity(&self, config: &protocol::GuardianConfig, request: &GuardianSignRequest) -> anyhow::Result<protocol::Hash4> {
        let identity = config.account_public_key().map_err(|error| anyhow::anyhow!(error))?;
        request.validate_authorization(config).map_err(|error| anyhow::anyhow!(error))?;
        ensure!(request.decode_trace()?.meta.public_key == identity, "relayer request account identity differs from the configured account");
        Ok(identity)
    }

    fn row(&self, nonce: u64) -> anyhow::Result<Option<Request>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(RELAYER_REQUEST)?;
        Ok(table.get(nonce)?.map(|row| decode(row.value())).transpose()?)
    }

    fn same_stage(saved: &Request, next: &Request) -> anyhow::Result<bool> {
        Ok(match (saved, next) {
            (Request::Request { request, deposit_tree_states }, Request::Request { request: next_request, deposit_tree_states: next_deposit_tree_states }) => request == next_request && deposit_tree_states == next_deposit_tree_states,
            (Request::Signed { request, deposit_tree_states, signatures }, Request::Signed { request: next_request, deposit_tree_states: next_deposit_tree_states, signatures: next_signatures }) => request == next_request && deposit_tree_states == next_deposit_tree_states && signatures == next_signatures,
            (Request::Proved { request, deposit_tree_states, signatures, endcap }, Request::Proved { request: next_request, deposit_tree_states: next_deposit_tree_states, signatures: next_signatures, endcap: next_endcap }) => request == next_request && deposit_tree_states == next_deposit_tree_states && signatures == next_signatures && endcap == next_endcap,
            (Request::Included { record }, Request::Included { record: next_record }) => serde_json::to_vec(record)? == serde_json::to_vec(next_record)?,
            _ => false,
        })
    }

    fn retain(&self, nonce: u64, next: &Request) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(RELAYER_REQUEST)?;
            if let Some(saved) = table.get(nonce)?.map(|row| decode(row.value())).transpose()? {
                if Self::same_stage(&saved, next)? { return Ok(()); }
                let advances = matches!((&saved, next),
                    (Request::Request { .. }, Request::Signed { .. })
                    | (Request::Signed { .. }, Request::Proved { .. }));
                ensure!(advances
                    && saved.request_text() == next.request_text()
                    && saved.account_key()? == next.account_key()?
                    && saved.deposit_tree_states() == next.deposit_tree_states()
                    && saved.signatures_text().is_none_or(|signatures| Some(signatures) == next.signatures_text()),
                    "relayer request row conflict");
            } else {
                ensure!(matches!(next, Request::Request { .. }), "relayer request stage conflict");
            }
            let bytes = encode(&next)?;
            table.insert(nonce, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    fn insert_chain_claims(&self, tx: &redb::WriteTransaction, claims: &[crate::bridge::propose_withdrawals::PendingWithdrawal]) -> anyhow::Result<()> {
        let mut table = tx.open_table(CHAIN_CLAIMS)?;
        let mut touched = BTreeSet::new();
        for claim in claims {
            let chain = u8::try_from(claim.destination_chain_index).context("claim destination chain does not fit chain_index")?;
            touched.insert(chain);
        }
        for chain in touched {
            let saved = match table.get(chain)? {
                Some(row) => decode_progress::<ChainClaims>(row.value())?,
                None => ChainClaims::default(),
            };
            let mut pending = saved.pending_claim_withdrawals;
            let before = pending.len();
            for claim in claims.iter().filter(|claim| claim.destination_chain_index == u64::from(chain)) {
                if saved.retired_claim_withdrawals.contains_key(&claim.leaf_hash) { continue; }
                // One pending entry per full leaf. An equal leaf is already
                // queued: a replay whose event metadata differs (event_id is
                // append ordering only, and an imported row carries 0) is not
                // a content conflict, so it is skipped, while a distinct leaf
                // that shares the nonce still gets its own entry.
                if pending.values().any(|existing| existing.leaf_hash == claim.leaf_hash) { continue; }
                pending.insert(claim.leaf_hash.clone(), claim.clone());
            }
            // Queued leaves stay untouched, so the length diff is exactly the newly queued leaves.
            if pending.len() != before {
                let next = ChainClaims { pending_claim_withdrawals: pending, ..saved };
                let bytes = encode_progress(&next)?;
                table.insert(chain, bytes.as_slice())?;
            }
        }
        Ok(())
    }

    /// Progress is usable once a request or the sole account row carries the configured account identity.
    fn progress_binding(&self, config: &protocol::GuardianConfig) -> anyhow::Result<bool> {
        let identity = config.account_public_key().map_err(|error| anyhow::anyhow!(error))?;
        let tx = self.db.begin_read()?;
        let requests = tx.open_table(RELAYER_REQUEST)?;
        if let Some(row) = requests.range::<u64>(..)?.next_back() {
            let (_, row) = row?;
            ensure!(decode(row.value())?.account_key()? == identity, "stored daemon progress is bound to a different account");
            return Ok(true);
        }
        let accounts = tx.open_table(GUARDIAN_ACCOUNT)?;
        let mut account_rows = accounts.iter()?;
        if let Some((_, row)) = account_rows.next().transpose()? {
            let account = decode_canonical::<GuardianAccount>(row.value())?;
            ensure!(account_rows.next().transpose()?.is_none(), "stored progress binds two different accounts");
            ensure!(account.account_public_key == identity, "stored daemon progress is bound to a different account");
            return Ok(true);
        }
        Ok(false)
    }

    /// A fresh database (no durable binding) may only carry default-valued progress rows.
    fn ensure_fresh_progress_default(&self) -> anyhow::Result<()> {
        let tx = self.db.begin_read()?;
        let claims = tx.open_table(CHAIN_CLAIMS)?;
        for item in claims.iter()? {
            let (_, row) = item?;
            ensure!(decode_progress::<ChainClaims>(row.value())? == ChainClaims::default(), "stored daemon progress has no durable account binding");
        }
        if let Some(row) = tx.open_table(FINALIZATION_BATCH)?.get(())? {
            ensure!(decode_progress::<FinalizationBatch>(row.value())? == FinalizationBatch::default(), "stored daemon progress has no durable account binding");
        }
        Ok(())
    }

    /// Sole writer of the finalization batch row. Decodes any existing row with the
    /// production progress guard inside the same transaction, so a poisoned batch
    /// aborts the commit before any claim row is touched.
    fn write_finalization_batch(&self, tx: &redb::WriteTransaction, batch: &FinalizationBatch) -> anyhow::Result<()> {
        let mut table = tx.open_table(FINALIZATION_BATCH)?;
        if let Some(row) = table.get(())? { decode_progress::<FinalizationBatch>(row.value())?; }
        table.insert((), encode_progress(batch)?.as_slice())?;
        Ok(())
    }

    /// Quarantine markers for indexed withdrawals whose Router token binding is
    /// wrong, keyed by (destination chain, global services event id).
    pub(crate) fn quarantined_withdrawals(&self) -> anyhow::Result<BTreeMap<(u8, i64), WithdrawalQuarantine>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(WITHDRAWAL_QUARANTINE)?;
        table.iter()?.map(|row| {
            let (key, value) = row?;
            Ok((key.value(), decode_progress::<WithdrawalQuarantine>(value.value())?))
        }).collect()
    }

    /// Writes new quarantine markers; a key already present keeps its original reason.
    pub(crate) fn quarantine_withdrawals(&self, quarantines: &BTreeMap<(u8, i64), WithdrawalQuarantine>) -> anyhow::Result<()> {
        if quarantines.is_empty() { return Ok(()); }
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(WITHDRAWAL_QUARANTINE)?;
            for (key, quarantine) in quarantines {
                if table.get(*key)?.is_some() { continue; }
                table.insert(*key, encode_progress(quarantine)?.as_slice())?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Number of quarantine markers for one destination chain. Together with
    /// the on-chain L2 append cursor this is the services stream position the
    /// next fetch starts from: every fetched event either appends or is marked.
    pub(crate) fn quarantine_marker_count(&self, chain: u8) -> anyhow::Result<u64> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(WITHDRAWAL_QUARANTINE)?;
        Ok(table.range::<(u8, i64)>((chain, i64::MIN)..=(chain, i64::MAX))?.count() as u64)
    }

    #[cfg(test)]
    pub(crate) fn test_write_raw_finalization_batch(&self, bytes: &[u8]) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(FINALIZATION_BATCH)?.insert((), bytes)?;
        tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_raw_finalization_batch(&self) -> anyhow::Result<Option<Vec<u8>>> {
        let tx = self.db.begin_read()?;
        Ok(tx.open_table(FINALIZATION_BATCH)?.get(())?.map(|row| row.value().to_vec()))
    }

    pub(crate) fn chain_claims(&self, config: &protocol::GuardianConfig) -> anyhow::Result<BTreeMap<u8, ChainClaims>> {
        if !self.progress_binding(config)? { self.ensure_fresh_progress_default()?; }
        let tx = self.db.begin_read()?;
        let table = tx.open_table(CHAIN_CLAIMS)?;
        let mut rows = BTreeMap::new();
        for item in table.iter()? {
            let (chain, row) = item?;
            rows.insert(chain.value(), decode_progress(row.value())?);
        }
        Ok(rows)
    }

    pub(crate) fn save_chain_claims(&self, config: &protocol::GuardianConfig, chain: u8, claims: &ChainClaims) -> anyhow::Result<()> {
        let bound = self.progress_binding(config)?;
        ensure!(bound || *claims == ChainClaims::default(), "non-default daemon progress requires a durable account binding");
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(CHAIN_CLAIMS)?;
            let bytes = encode_progress(claims)?;
            table.insert(chain, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn finalization_batch(&self, config: &protocol::GuardianConfig) -> anyhow::Result<FinalizationBatch> {
        if !self.progress_binding(config)? { self.ensure_fresh_progress_default()?; }
        let tx = self.db.begin_read()?;
        let table = tx.open_table(FINALIZATION_BATCH)?;
        Ok(match table.get(())? {
            Some(row) => decode_progress(row.value())?,
            None => FinalizationBatch::default(),
        })
    }

    pub(crate) fn save_finalization_batch(&self, config: &protocol::GuardianConfig, batch: &FinalizationBatch) -> anyhow::Result<()> {
        let bound = self.progress_binding(config)?;
        ensure!(bound || *batch == FinalizationBatch::default(), "non-default daemon progress requires a durable account binding");
        let tx = self.db.begin_write()?;
        self.write_finalization_batch(&tx, batch)?;
        tx.commit()?;
        Ok(())
    }
    /// The shared batch and every chain-claims row are one recovery image.
    /// A crash between them would resume a range against a different claim set.
    pub(crate) fn save_claims_and_batch(&self, config: &protocol::GuardianConfig, claims: &BTreeMap<u8, ChainClaims>, batch: &FinalizationBatch) -> anyhow::Result<()> {
        let bound = self.progress_binding(config)?;
        ensure!(bound || (batch == &FinalizationBatch::default() && claims.values().all(|row| row == &ChainClaims::default())), "non-default daemon progress requires a durable account binding");
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(CHAIN_CLAIMS)?;
            let known = table.iter()?.map(|item| {
                let (chain, row) = item?;
                decode_progress::<ChainClaims>(row.value())?;
                Ok(chain.value())
            }).collect::<anyhow::Result<BTreeSet<_>>>()?;
            for chain in known.iter().filter(|chain| !claims.contains_key(chain)) {
                let bytes = encode_progress(&ChainClaims::default())?;
                table.insert(*chain, bytes.as_slice())?;
            }
            for (chain, row) in claims {
                let bytes = encode_progress(row)?;
                table.insert(*chain, bytes.as_slice())?;
            }
            self.write_finalization_batch(&tx, batch)?;
        }
        tx.commit()?;
        Ok(())
    }


    pub(crate) fn save_finalization_and_claims(&self, config: &protocol::GuardianConfig, batch: &FinalizationBatch, claims: &[crate::bridge::propose_withdrawals::PendingWithdrawal]) -> anyhow::Result<()> {
        let bound = self.progress_binding(config)?;
        ensure!(bound || (batch == &FinalizationBatch::default() && claims.is_empty()), "non-default daemon progress requires a durable account binding");
        let tx = self.db.begin_write()?;
        {
            self.write_finalization_batch(&tx, batch)?;
            self.insert_chain_claims(&tx, claims)?;
        }
        tx.commit()?;
        Ok(())
    }



    pub(crate) fn save_request(&self, config: &protocol::GuardianConfig, request: &JsonText<GuardianSignRequest>, deposit_tree_states: &[DepositTreeState], claims: &[crate::bridge::propose_withdrawals::PendingWithdrawal]) -> anyhow::Result<()> {
        let decoded = request.decode()?;
        let identity = self.current_identity(config, &decoded)?;
        validate_changed_deposit_tree_states(&decoded, deposit_tree_states).map_err(|error| anyhow::anyhow!(error))?;
        let tx = self.db.begin_write()?;
        {
            let mut requests = tx.open_table(RELAYER_REQUEST)?;
            let previous = decoded.session_nonce.checked_sub(1).context("relayer nonce starts at zero")?;
            // The authoritative account cursor bounds the retained suffix: a fresh row may only
            // extend imported_nonce + 1, so a pruned suffix never grows a stale lower row.
            let cursor = match tx.open_table(GUARDIAN_ACCOUNT)?.get((decoded.network_magic, decoded.user_id))? {
                Some(row) => {
                    let account: GuardianAccount = decode_canonical(row.value())?;
                    ensure!((account.network_magic, account.user_id) == (decoded.network_magic, decoded.user_id), "account key differs from encoded identity");
                    account.validate().map_err(|error| anyhow::anyhow!(error))?;
                    account.imported_nonce.unwrap_or(0)
                }
                None => 0,
            };
            // A journal rebuilt by `restore-bridge-state` keeps the account cursor but no
            // request rows. The predecessor Included row is required everywhere except exactly
            // at that boundary, where the row the cursor names was erased on purpose.
            if previous != 0 && previous != cursor {
                ensure!(matches!(requests.get(previous)?.map(|row| decode(row.value())).transpose()?, Some(Request::Included { .. })), "relayer request prefix is incomplete");
            }
            for item in requests.range(decoded.session_nonce..)? {
                let (nonce, row) = item?;
                let nonce = nonce.value();
                let saved = decode(row.value())?;
                if !matches!(saved, Request::Included { .. }) {
                    ensure!(nonce == decoded.session_nonce && saved.request_text() == request.as_str() && saved.account_key()? == identity && saved.deposit_tree_states() == deposit_tree_states, "multiple unresolved account requests");
                }
            }
            if requests.get(decoded.session_nonce)?.is_none() {
                ensure!(decoded.session_nonce == cursor.checked_add(1).context("relayer nonce overflow")?, "relayer request does not extend the imported account cursor");
                self.insert_chain_claims(&tx, claims)?;
                let next = Request::Request { request: request.as_str().to_owned(), deposit_tree_states: deposit_tree_states.to_vec() };
                let bytes = encode(&next)?;
                requests.insert(decoded.session_nonce, bytes.as_slice())?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Point-reads the unresolved request at the authoritative account cursor + 1 instead of scanning the whole journal.
    pub(crate) fn pending_request(&self) -> anyhow::Result<Option<JsonText<GuardianSignRequest>>> {
        let tx = self.db.begin_read()?;
        let cursor = {
            let accounts = tx.open_table(GUARDIAN_ACCOUNT)?;
            let mut rows = accounts.iter()?;
            let imported = match rows.next().transpose()? {
                Some((key, row)) => {
                    ensure!(rows.next().transpose()?.is_none(), "stored progress binds two different accounts");
                    let account: GuardianAccount = decode_canonical(row.value())?;
                    ensure!(key.value() == (account.network_magic, account.user_id), "account key differs from encoded identity");
                    account.imported_nonce
                }
                None => None,
            };
            imported.unwrap_or(0)
        };
        let saved = match tx.open_table(RELAYER_REQUEST)?.get(cursor.checked_add(1).context("relayer nonce overflow")?)? {
            Some(row) => decode(row.value())?,
            None => return Ok(None),
        };
        if matches!(saved, Request::Included { .. }) { return Ok(None); }
        Ok(Some(JsonText::parse(saved.request_text().to_owned()).map_err(|error| anyhow::anyhow!(error))?))
    }

    pub(crate) fn load_session(&self, nonce: u64, request_id: protocol::Hex32) -> anyhow::Result<(JsonText<GuardianSignRequest>, Option<GuardianSessionRecord>)> {
        let saved = self.row(nonce)?.context("guardian request not yet archived")?;
        let request_json = JsonText::<GuardianSignRequest>::parse(saved.request_text().to_owned()).map_err(|error| anyhow::anyhow!(error))?;
        let request = request_json.decode()?;
        ensure!(request.session_nonce == nonce, "archived guardian request nonce mismatch");
        ensure!(request.request_id().map_err(|error| anyhow::anyhow!(error))? == request_id, "archived guardian request identity mismatch");
        let record = match saved { Request::Included { record, .. } => Some(record), _ => None };
        Ok((request_json, record))
    }

    pub(crate) fn save_signatures(&self, nonce: u64, signatures: &MultisigSignatures) -> anyhow::Result<()> {
        ensure!(signatures.member_indices.len() == 2 && signatures.signatures.len() == 2 && signatures.member_indices[0] < signatures.member_indices[1] && signatures.member_indices[1] < 3, "exactly two sorted signatures required");
        let saved = self.row(nonce)?.context("guardian request not yet archived")?;
        let text = serde_json::to_string(signatures)?;
        let next = match saved {
            Request::Request { request, deposit_tree_states } => Request::Signed { request, deposit_tree_states, signatures: text },
            Request::Signed { signatures, .. } | Request::Proved { signatures, .. } => {
                ensure!(signatures == text, "relayer signature row conflict");
                return Ok(());
            }
            Request::Included { record, .. } => {
                ensure!(record.signatures_json.as_str() == text, "relayer signature row conflict");
                return Ok(());
            }
        };
        self.retain(nonce, &next)
    }

    pub(crate) fn signatures(&self, nonce: u64) -> anyhow::Result<Option<MultisigSignatures>> {
        Ok(match self.row(nonce)? {
            Some(saved) => saved.signatures_text().map(|text| serde_json::from_str(text)).transpose()?,
            None => None,
        })
    }

    pub(crate) fn save_proof(&self, nonce: u64, proof: &[u8]) -> anyhow::Result<()> {
        ensure!(!proof.is_empty(), "archived proof is empty");
        let saved = self.row(nonce)?.context("guardian request not yet archived")?;
        let next = match saved {
            Request::Signed { request, deposit_tree_states, signatures } => Request::Proved { request, deposit_tree_states, signatures, endcap: proof.to_vec() },
            Request::Proved { endcap, .. } => {
                ensure!(endcap == proof, "relayer proof row conflict");
                return Ok(());
            }
            Request::Included { record, .. } => {
                ensure!(record.proof_bytes().map_err(|error| anyhow::anyhow!(error))? == proof, "relayer proof row conflict");
                return Ok(());
            }
            Request::Request { .. } => anyhow::bail!("relayer request stage conflict"),
        };
        self.retain(nonce, &next)
    }

    pub(crate) fn proof(&self, nonce: u64) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(match self.row(nonce)? {
            Some(Request::Proved { endcap, .. }) => Some(endcap),
            Some(Request::Included { record, .. }) => Some(record.proof_bytes().map_err(|error| anyhow::anyhow!(error))?),
            _ => None,
        })
    }

    /// Pending deposit-tree states bound to this exact request. Included and unknown nonces return an empty slice.
    pub(crate) fn pending_deposit_tree_states(&self, nonce: u64) -> anyhow::Result<Vec<DepositTreeState>> {
        Ok(self.row(nonce)?.map(|saved| saved.deposit_tree_states().to_vec()).unwrap_or_default())
    }

    pub(crate) fn load_account(&self, network: u64, user: u64) -> anyhow::Result<Option<GuardianAccount>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(GUARDIAN_ACCOUNT)?;
        let Some(row) = table.get((network, user))? else { return Ok(None); };
        let account: GuardianAccount = decode_canonical(row.value())?;
        ensure!((account.network_magic, account.user_id) == (network, user), "account key differs from encoded identity");
        account.validate().map_err(|error| anyhow::anyhow!(error))?;
        Ok(Some(account))
    }
    /// Records the verified genesis account, the sole authorization binding a fresh
    /// daemon has before any request exists. Inserts it only when absent; an existing
    /// row is retained unchanged, including its nonce, checkpoint, frontiers, and halt.
    pub(crate) fn ensure_genesis_account(&self, config: &protocol::GuardianConfig, genesis_leaf: protocol::Hash4) -> anyhow::Result<()> {
        let network = config.network_magic().map_err(|error| anyhow::anyhow!(error))?;
        let identity = config.account_public_key().map_err(|error| anyhow::anyhow!(error))?;
        let created = GuardianAccount {
            network_magic: network, user_id: BRIDGE_USER_ID, state: protocol::GuardianAccountState::Active,
            last_checkpoint_id: 0, last_checkpoint_hash: genesis_leaf, imported_nonce: None,
            account_public_key: identity, imported_ending_leaf: None, withdrawal_chains: Vec::new(), halt_reason: None,
        };
        created.validate().map_err(|error| anyhow::anyhow!(error))?;
        let created_bytes = encode_canonical(&created)?;
        let tx = self.db.begin_write()?;
        {
            let mut accounts = tx.open_table(GUARDIAN_ACCOUNT)?;
            let has_account = {
                let mut stored = accounts.iter()?;
                let first = stored.next().transpose()?;
                if let Some((key, row)) = first {
                    let saved: GuardianAccount = decode_canonical(row.value())?;
                    ensure!(stored.next().transpose()?.is_none(), "initialized guardian account binds a different identity");
                    ensure!(key.value() == (saved.network_magic, saved.user_id), "account key differs from encoded identity");
                    ensure!((saved.network_magic, saved.user_id, saved.account_public_key) == (network, BRIDGE_USER_ID, identity), "initialized guardian account differs from the configured account");
                    saved.validate().map_err(|error| anyhow::anyhow!(error))?;
                    true
                } else {
                    false
                }
            };
            if !has_account {
                accounts.insert((network, BRIDGE_USER_ID), created_bytes.as_slice())?;
            }
        }
        tx.commit()?;
        Ok(())
    }



    pub(crate) fn load_deposit_tree_states(&self, network: u64, user: u64) -> anyhow::Result<Vec<DepositTreeState>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(DEPOSIT_TREE_STATES)?;
        let mut rows = Vec::new();
        for entry in table.range(DepositTreeKey(network, user, 0)..=DepositTreeKey(network, user, u8::MAX))? {
            let (key, value) = entry?;
            rows.push((key.value(), value.value().to_vec()));
        }
        drop(table);
        let mut deposit_tree_states = Vec::with_capacity(rows.len());
        for (key, bytes) in rows {
            let state: DepositTreeState = decode_canonical(&bytes)?;
            ensure!(key == DepositTreeKey(network, user, state.anchor.chain_index), "deposit tree key differs from encoded chain");
            state.validate().map_err(|error| anyhow::anyhow!(error))?;
            deposit_tree_states.push(state);
        }
        Ok(deposit_tree_states)
    }

    #[cfg(test)]
    fn inclusion_session_nonce(&self, network: u64, user: u64, sender: u32, contract: u32, nonce: [u32; 8]) -> anyhow::Result<Option<u64>> {
        let tx = self.db.begin_read()?;
        Ok(tx.open_table(INCLUDED_WITHDRAWAL_BURNS)?.get(WithdrawalBurnKey(network, user, sender, contract, nonce))?.map(|row| row.value()))
    }

    #[cfg(test)]
    fn nonce_inclusion_session(&self, network: u64, user: u64, chain: u8, nonce: [u32; 8]) -> anyhow::Result<Option<u64>> {
        let tx = self.db.begin_read()?;
        Ok(tx.open_table(WITHDRAWAL_NONCE)?.get(NonceKey(network, user, chain, nonce))?.map(|row| row.value()))
    }

    /// Persists one existing halt reason on this account alone. An already halted row keeps its reason.
    pub(crate) fn halt_account(&self, network: u64, user: u64, reason: HaltReason) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut accounts = tx.open_table(GUARDIAN_ACCOUNT)?;
            let account = {
                let row = accounts.get((network, user))?.context("guardian account missing")?;
                let account: GuardianAccount = decode_canonical(row.value())?;
                ensure!((account.network_magic, account.user_id) == (network, user), "account key differs from encoded identity");
                account.validate().map_err(|error| anyhow::anyhow!(error))?;
                account
            };
            if account.state == guardian_common::protocol::GuardianAccountState::Active { halt_account(&mut accounts, &account, reason)?; }
        }
        tx.commit()?;
        Ok(())
    }

    /// Included transition, changed deposit-tree states, latest-inclusion session-nonce metadata, and the sole account checkpoint in one commit.
    /// `checkpoint_hash` is the authenticated checkpoint leaf hash. A conflicting replay of an included nonce halts and never rewinds.
    /// Retention prunes every request row older than the imported nonce in this same commit; at most one pending successor survives.
    pub(crate) fn import_verified(&self, config: &protocol::GuardianConfig, session: &GuardianSession, deposit_tree_states: &[DepositTreeState], checkpoint_id: u64, checkpoint_hash: protocol::Hash4) -> anyhow::Result<()> {
        let request = session.record.validate(config).map_err(|error| anyhow::anyhow!(error))?;
        let identity = self.current_identity(config, &request)?;
        ensure!((request.network_magic, request.user_id, request.session_nonce) == (session.network_magic, session.user_id, session.nonce), "imported session identity mismatch");
        ensure!(session.record.included_checkpoint_id == checkpoint_id && session.record.included_checkpoint_hash == checkpoint_hash, "imported checkpoint is not the bound leaf");
        validate_changed_deposit_tree_states(&request, deposit_tree_states).map_err(|error| anyhow::anyhow!(error))?;
        ensure!(session.withdrawal_appends.len() == request.withdrawal_records.len() && session.withdrawal_appends.iter().zip(&request.withdrawal_records).all(|(append, burn)| &append.burn == burn && append.chain_index == burn.destination_chain_index), "imported appends differ from the request");
        let saved = self.row(session.nonce)?;
        if let Some(saved) = &saved {
            if !matches!(saved, Request::Included { .. }) {
                // Staged rows reject mismatches before any account state is touched. A retained
                // Included row defers classification into the write transaction below, so an
                // exact replay stays idempotent and a conflicting one persists the halt.
                ensure!(saved.request_text() == session.record.request_json.as_str(), "included request differs from archived request");
                ensure!(saved.deposit_tree_states() == deposit_tree_states, "included deposit-tree states differ from the staged request");
                if let Some(signatures) = saved.signatures_text() { ensure!(signatures == session.record.signatures_json.as_str(), "relayer signature row conflict"); }
                if let Some(proof) = self.proof(session.nonce)? { ensure!(proof == session.record.proof_bytes().map_err(|error| anyhow::anyhow!(error))?, "relayer proof row conflict"); }
            }
        }
        let tx = self.db.begin_write()?;
        {
            let current = {
                let requests = tx.open_table(RELAYER_REQUEST)?;
                let decoded = requests.get(session.nonce)?.map(|row| decode(row.value())).transpose()?;
                decoded
            };
            let mut accounts = tx.open_table(GUARDIAN_ACCOUNT)?;
            let key = (session.network_magic, session.user_id);
            let account = match accounts.get(key)? {
                Some(row) => {
                    let account: GuardianAccount = decode_canonical(row.value())?;
                    account.validate().map_err(|error| anyhow::anyhow!(error))?;
                    ensure!((account.network_magic, account.user_id) == key, "account key differs from encoded identity");
                    account
                }
                None => fresh_account(session, identity, checkpoint_id, checkpoint_hash),
            };
            if account.state == guardian_common::protocol::GuardianAccountState::Halted { anyhow::bail!("halted account refuses import"); }
            let included_row = Request::Included { record: session.record.clone() };
            let same_included = current.as_ref().is_some_and(|row| matches!(row, Request::Included { .. }) && Self::same_stage(row, &included_row).unwrap_or(false));
            // An exact replay of the archived Included bytes is idempotent on the immutable
            // per-nonce row and must return Ok before any cursor halt. At the current nonce
            // the account still opens this session's own checkpoint, so divergent leaves
            // there fall through to the consumed-differently halt below.
            if same_included && (account.imported_nonce.is_some_and(|imported| imported > session.nonce)
                || (account.imported_nonce == Some(session.nonce) && account.last_checkpoint_hash == checkpoint_hash && account.imported_ending_leaf == Some(session.ending_leaf_hash))) {
                if account.imported_nonce == Some(session.nonce) {
                    let included = load_changed_deposit_tree_states(&tx, session.network_magic, session.user_id, deposit_tree_states)?;
                    ensure!(included == deposit_tree_states, "included nonce consumed differently");
                }
                return Ok(());
            }
            if current.is_none() && account.imported_nonce.is_some_and(|imported| imported > session.nonce) {
                // Retention already pruned this nonce's Included row and the imported cursor
                // covers it: a stale replay is refused without halting the account.
                return Err(GuardianSignError::SessionHistoryUnavailable.into());
            }
            if account.imported_nonce.is_some_and(|imported| imported > session.nonce) || current.as_ref().is_some_and(|row| matches!(row, Request::Included { .. })) {
                halt_account(&mut accounts, &account, HaltReason::NonceConsumedDifferently)?;
                drop(accounts);
                tx.commit()?;
                anyhow::bail!("included nonce consumed differently");
            }
            if checkpoint_id == account.last_checkpoint_id && checkpoint_hash != account.last_checkpoint_hash {
                halt_account(&mut accounts, &account, HaltReason::CheckpointConflict)?;
                drop(accounts);
                tx.commit()?;
                anyhow::bail!("checkpoint leaf conflict halted the account");
            }
            if let Some(current) = current.filter(|row| !matches!(row, Request::Included { .. })) {
                ensure!(current.request_text() == session.record.request_json.as_str() && current.deposit_tree_states() == deposit_tree_states, "included request differs from archived request");
            }
            let included = load_deposit_tree_state_rows(&tx, session.network_magic, session.user_id)?;
            let (advanced, included) = match advance_included_account(&account, &included, session, deposit_tree_states, checkpoint_id, checkpoint_hash) {
                Ok(advanced) => advanced,
                Err(error @ (GuardianSignError::StateMismatch | GuardianSignError::WithdrawalNonceConflict)) => {
                    halt_account(&mut accounts, &account, if matches!(error, GuardianSignError::WithdrawalNonceConflict) { HaltReason::AppendHistoryMismatch } else { HaltReason::IncludedTransitionMissing })?;
                    drop(accounts);
                    tx.commit()?;
                    anyhow::bail!("included transition conflict halted the account");
                }
                Err(error) => return Err(anyhow::anyhow!(error)),
            };
            write_deposit_tree_states(&tx, session.network_magic, session.user_id, &included)?;
            write_batch_indexes(&tx, session)?;
            let bytes = encode_canonical(&advanced)?;
            accounts.insert(key, bytes.as_slice())?;
            drop(accounts);
            let mut requests = tx.open_table(RELAYER_REQUEST)?;
            let bytes = encode(&included_row)?;
            requests.insert(session.nonce, bytes.as_slice())?;
            // Retention: the just-advanced imported cursor makes every older row dead weight, so
            // they leave in this same commit; at most one pending successor survives and a larger
            // future tail fails closed instead of being silently dropped.
            let successor = session.nonce.checked_add(1).context("relayer nonce overflow")?;
            let mut stale = Vec::new();
            for row in requests.range::<u64>(..session.nonce)? { stale.push(row?.0.value()); }
            for nonce in stale { requests.remove(nonce)?; }
            let mut successors = 0u64;
            for row in requests.range::<u64>(successor..)? {
                let (key, value) = row?;
                successors += 1;
                ensure!(successors == 1 && key.value() == successor && !matches!(decode(value.value())?, Request::Included { .. }), "retained request suffix exceeds the single pending successor");
            }
            let claims = session.withdrawal_appends.iter().map(|append| Ok(crate::bridge::propose_withdrawals::PendingWithdrawal {
                event_id: 0,
                checkpoint_id,
                user_id: u64::from(append.burn.sender_user_id),
                sender_user_id: u64::from(append.burn.sender_user_id),
                contract_id: u64::from(append.burn.token_contract_id),
                destination_chain_index: u64::from(append.burn.destination_chain_index),
                token_address: append.burn.token,
                amount: append.burn.amount,
                recipient: append.burn.recipient,
                nonce: append.burn.nonce,
                leaf_hash: crate::bridge::propose_withdrawals::compute_withdrawal_leaf_hash(u64::from(append.burn.sender_user_id), append.burn.recipient, append.burn.token, append.burn.amount, append.burn.nonce, u64::from(append.burn.destination_chain_index), u64::from(append.burn.token_contract_id))?,
            })).collect::<anyhow::Result<Vec<_>>>()?;
            self.insert_chain_claims(&tx, &claims)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn sessions(&self, after_nonce: u64, limit: u8) -> anyhow::Result<GuardianSessionsResponse> {
        ensure!((1..=64).contains(&limit), "history limit must be 1..64");
        let start = after_nonce.checked_add(1).context("history nonce overflow")?;
        let tx = self.db.begin_read()?;
        let table = tx.open_table(RELAYER_REQUEST)?;
        let mut response = GuardianSessionsResponse { sessions: Vec::new(), next_after_nonce: after_nonce, has_more: false };
        for item in table.range(start..)? {
            let (nonce, row) = item?;
            let nonce = nonce.value();
            let Request::Included { record, .. } = decode(row.value())? else { break };
            let decoded = record.request_json.decode()?;
            if decoded.session_nonce != nonce { break; }
            if response.sessions.len() == usize::from(limit) { response.has_more = true; break; }
            response.next_after_nonce = nonce;
            response.sessions.push(record);
        }
        Ok(response)
    }


}

fn encode(value: &Request) -> anyhow::Result<Vec<u8>> {
    let json = serde_json::to_vec(value)?;
    let frame = protocol::encode_record(&json).map_err(|error| anyhow::anyhow!(error))?;
    ensure!(protocol::decode_record(&frame).map_err(|error| anyhow::anyhow!(error))? == json, "relayer request frame is not canonical");
    Ok(frame)
}

fn decode(bytes: &[u8]) -> anyhow::Result<Request> {
    let json = protocol::decode_record(bytes).map_err(|error| anyhow::anyhow!(error)).context("relayer request row rejected")?;
    let value: Request = serde_json::from_slice(&json).context("relayer request row rejected")?;
    ensure!(serde_json::to_vec(&value)? == json, "relayer request row is not canonical");
    if let Request::Request { deposit_tree_states, .. } | Request::Signed { deposit_tree_states, .. } | Request::Proved { deposit_tree_states, .. } = &value {
        for state in deposit_tree_states { state.validate().map_err(|error| anyhow::anyhow!(error))?; }
    }
    Ok(value)
}

fn validate_legacy(bytes: &[u8], config: &protocol::GuardianConfig, nonce: u64) -> anyhow::Result<Request> {
    let value: Request = serde_json::from_slice(bytes).context("relayer request row rejected")?;
    ensure!(serde_json::to_vec(&value)? == bytes, "relayer request row is not canonical");
    validate_request(&value, config, nonce)?;
    Ok(value)
}

fn validate_request(value: &Request, config: &protocol::GuardianConfig, nonce: u64) -> anyhow::Result<()> {
    let request = GuardianSignRequest::parse_retained(value.request_text().as_bytes()).map_err(|error| anyhow::anyhow!(error))?;
    ensure!(request.session_nonce == nonce, "archived guardian request nonce mismatch");
    request.validate_authorization(config).map_err(|error| anyhow::anyhow!(error))?;
    match value {
        Request::Request { deposit_tree_states, .. } | Request::Signed { deposit_tree_states, .. } | Request::Proved { deposit_tree_states, .. } => {
            for state in deposit_tree_states { state.validate().map_err(|error| anyhow::anyhow!(error))?; }
            validate_changed_deposit_tree_states(&request, deposit_tree_states).map_err(|error| anyhow::anyhow!(error))?;
            if let Request::Signed { signatures, .. } | Request::Proved { signatures, .. } = value {
                let parsed: MultisigSignatures = serde_json::from_str(signatures)?;
                ensure!(serde_json::to_string(&parsed)? == *signatures, "relayer signature row is not canonical");
            }
            if let Request::Proved { endcap, .. } = value { ensure!(!endcap.is_empty(), "archived proof is empty"); }
        }
        Request::Included { record } => { record.validate(config).map_err(|error| anyhow::anyhow!(error))?; }
    }
    Ok(())
}

/// Offline schema migration. The caller holds the exclusive database. Marker 2 rewrites every
/// `relayer_request` row in one transaction; marker 3 keeps every byte and only adds the empty
/// withdrawal quarantine table; marker 4 additionally validates the retained suffix against the
/// authoritative account cursor. Neither migration prunes: older rows only leave with the next
/// authenticated import, so a transitional journal may still hold the full history.
/// Keys are collected first and each value is replaced before the next row is read.
pub(crate) fn migrate_relayer_journal(db: &redb::Database, config: &protocol::GuardianConfig) -> anyhow::Result<u64> {
    let marker = journal_marker(db)?;
    if marker == JOURNAL_SCHEMA_VERSION { return Ok(validate_current_requests(db, config)?); }
    if marker == JOURNAL_SCHEMA_V3 {
        let tx = db.begin_write()?;
        if journal_marker_in_write(&tx)? != JOURNAL_SCHEMA_V3 { anyhow::bail!("{LEGACY_JOURNAL}"); }
        tx.open_table(WITHDRAWAL_QUARANTINE)?;
        tx.open_table(JOURNAL_SCHEMA)?.insert((), JOURNAL_SCHEMA_VERSION)?;
        tx.commit()?;
        return Ok(validate_current_requests(db, config)?);
    }
    if marker != JOURNAL_SCHEMA_V2 { anyhow::bail!("{LEGACY_JOURNAL}"); }
    let keys = request_keys(db)?;
    let tx = db.begin_write()?;
    if journal_marker_in_write(&tx)? != JOURNAL_SCHEMA_V2 { anyhow::bail!("{LEGACY_JOURNAL}"); }
    let count = rewrite_request_rows(&tx, &keys, config)?;
    // The retained-suffix contract is checked against the uncommitted write view, so a rejected
    // history leaves the marker bump and every rewritten row uncommitted.
    let checked = validate_retained_suffix(&tx.open_table(GUARDIAN_ACCOUNT)?, &tx.open_table(RELAYER_REQUEST)?, config)?;
    ensure!(checked == count, "relayer request migration count mismatch");
    tx.open_table(WITHDRAWAL_QUARANTINE)?;
    tx.open_table(JOURNAL_SCHEMA)?.insert((), JOURNAL_SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(count)
}

fn journal_marker(db: &redb::Database) -> anyhow::Result<u64> {
    let tx = db.begin_read()?;
    ensure!(tx.list_multimap_tables()?.next().is_none(), "{LEGACY_JOURNAL}");
    let names = tx.list_tables()?.map(|table| table.name().to_owned()).collect::<std::collections::BTreeSet<_>>();
    // The table set must match the marker: "eight tables with marker 4" and
    // "nine tables with marker 3" are both broken journals, not migrations.
    // Marker 2 shares the schema 3 set: its migration rewrites rows only.
    let full: std::collections::BTreeSet<String> = RELAYER_TABLES.into_iter().map(str::to_owned).collect();
    let schema = tx.open_table(JOURNAL_SCHEMA)?;
    ensure!(schema.len()? == 1, "{LEGACY_JOURNAL}");
    let marker = match schema.get(())? { Some(row) => row.value(), None => anyhow::bail!("{LEGACY_JOURNAL}") };
    match marker {
        JOURNAL_SCHEMA_VERSION => ensure!(names == full, "{LEGACY_JOURNAL}"),
        JOURNAL_SCHEMA_V3 | JOURNAL_SCHEMA_V2 => {
            let mut without_quarantine = full;
            without_quarantine.remove("withdrawal_quarantine");
            ensure!(names == without_quarantine, "{LEGACY_JOURNAL}");
        }
        _ => anyhow::bail!("{LEGACY_JOURNAL}"),
    }
    Ok(marker)
}

fn journal_marker_in_write(tx: &redb::WriteTransaction) -> anyhow::Result<u64> {
    let schema = tx.open_table(JOURNAL_SCHEMA)?;
    ensure!(schema.len()? == 1, "{LEGACY_JOURNAL}");
    let value = schema.get(())?;
    match value { Some(row) => Ok(row.value()), None => anyhow::bail!("{LEGACY_JOURNAL}") }
}

fn request_keys(db: &redb::Database) -> anyhow::Result<Vec<u64>> {
    let tx = db.begin_read()?;
    let mut keys = Vec::new();
    let mut previous = 0u64;
    for (index, row) in tx.open_table(RELAYER_REQUEST)?.iter()?.enumerate() {
        let nonce = row?.0.value();
        ensure!(index == 0 && nonce == 1 || nonce == previous.checked_add(1).context("relayer nonce overflow")?, "relayer request prefix is incomplete");
        previous = nonce;
        keys.push(nonce);
    }
    Ok(keys)
}

fn rewrite_request_rows(tx: &redb::WriteTransaction, keys: &[u64], config: &protocol::GuardianConfig) -> anyhow::Result<u64> {
    let mut requests = tx.open_table(RELAYER_REQUEST)?;
    for nonce in keys {
        let guard = requests.get(*nonce)?.context(LEGACY_JOURNAL)?;
        let raw = guard.value();
        let saved = validate_legacy(raw, config, *nonce)?;
        let frame = protocol::encode_record(raw).map_err(|error| anyhow::anyhow!(error))?;
        ensure!(protocol::decode_record(&frame).map_err(|error| anyhow::anyhow!(error))? == raw, "relayer request frame is not canonical");
        let decoded = decode(&frame)?;
        validate_request(&decoded, config, *nonce)?;
        ensure!(decoded.request_text() == saved.request_text(), "relayer request frame is not canonical");
        drop(guard);
        requests.insert(*nonce, frame.as_slice())?;
    }
    Ok(keys.len() as u64)
}

/// Validates the retained `relayer_request` suffix against the authoritative account cursor.
/// Rows form one contiguous run that may start above nonce 1 (older rows are pruned by the next
/// authenticated import). With Included history the run must end at the imported nonce's Included
/// record, whose checkpoint binds the account cursor, plus at most one pending successor. A reset
/// journal has no Included history: the cursor may then stand alone, or with exactly one unresolved
/// successor at `imported_nonce + 1`. A journal without an imported cursor may only hold a single
/// pending row at nonce 1.
fn validate_retained_suffix(accounts: &impl ReadableTable<(u64, u64), &'static [u8]>, requests: &impl ReadableTable<u64, &'static [u8]>, config: &protocol::GuardianConfig) -> anyhow::Result<u64> {
    let identity = config.account_public_key().map_err(|error| anyhow::anyhow!(error))?;
    let authority = {
        let mut rows = accounts.iter()?;
        match rows.next().transpose()? {
            Some((key, row)) => {
                ensure!(rows.next().transpose()?.is_none(), "stored progress binds two different accounts");
                let account: GuardianAccount = decode_canonical(row.value())?;
                ensure!(key.value() == (account.network_magic, account.user_id), "account key differs from encoded identity");
                ensure!(account.account_public_key == identity, "stored daemon progress is bound to a different account");
                account.validate().map_err(|error| anyhow::anyhow!(error))?;
                Some(account)
            }
            None => None,
        }
    };
    let mut count = 0u64;
    let mut previous: Option<u64> = None;
    let mut pending_nonce: Option<u64> = None;
    let mut included: Option<(u64, u64, protocol::Hash4)> = None;
    for row in requests.iter()? {
        let (key, bytes) = row?;
        let nonce = key.value();
        ensure!(nonce != 0, "relayer request row rejects nonce zero");
        ensure!(previous.is_none_or(|previous| previous.checked_add(1) == Some(nonce)), "relayer request prefix is incomplete");
        previous = Some(nonce);
        let raw = bytes.value();
        let value = decode(raw)?;
        validate_request(&value, config, nonce)?;
        match &value {
            Request::Included { record } => included = Some((nonce, record.included_checkpoint_id, record.included_checkpoint_hash)),
            _ => {
                ensure!(pending_nonce.is_none(), "multiple unresolved account requests");
                pending_nonce = Some(nonce);
            }
        }
        count += 1;
    }
    let Some(account) = authority.as_ref() else {
        ensure!(included.is_none() && (count == 0 || (count == 1 && previous == Some(1))), "relayer request suffix requires an imported account cursor");
        return Ok(count);
    };
    match account.imported_nonce {
        None => ensure!(included.is_none() && (count == 0 || (count == 1 && previous == Some(1))), "relayer request suffix requires an imported account cursor"),
        // A journal rebuilt by `restore-bridge-state` carries the account cursor and no request
        // rows at all. Until the next request is saved it holds nothing; once that request exists
        // it holds exactly one unresolved row at imported_nonce + 1. Both are valid. Any Included
        // history keeps the original contract: the retained run must end on the cursor's own
        // Included record, bound to the account checkpoint, plus at most that one successor.
        Some(imported) if included.is_none() => {
            ensure!(pending_nonce.is_none() && count == 0 || pending_nonce == imported.checked_add(1) && count == 1, "relayer request prefix is incomplete");
        }
        Some(imported) => {
            let (nonce, checkpoint_id, checkpoint_hash) = included.expect("included history");
            ensure!(nonce == imported, "authoritative included nonce is missing from the retained suffix");
            ensure!(checkpoint_id == account.last_checkpoint_id && checkpoint_hash == account.last_checkpoint_hash, "authoritative included checkpoint differs from the account cursor");
            ensure!(pending_nonce.is_none_or(|pending_nonce| Some(pending_nonce) == imported.checked_add(1)), "relayer request prefix is incomplete");
        }
    }
    Ok(count)
}

fn validate_current_requests(db: &redb::Database, config: &protocol::GuardianConfig) -> anyhow::Result<u64> {
    let tx = db.begin_read()?;
    validate_retained_suffix(&tx.open_table(GUARDIAN_ACCOUNT)?, &tx.open_table(RELAYER_REQUEST)?, config)
}
fn deposit_tree_key_span(network: u64, user: u64) -> impl std::ops::RangeBounds<DepositTreeKey> { DepositTreeKey(network, user, 0)..=DepositTreeKey(network, user, u8::MAX) }

fn load_deposit_tree_state_rows(tx: &redb::WriteTransaction, network: u64, user: u64) -> anyhow::Result<Vec<DepositTreeState>> {
    let table = tx.open_table(DEPOSIT_TREE_STATES)?;
    let mut deposit_tree_states = Vec::new();
    for entry in table.range(deposit_tree_key_span(network, user))? {
        let (key, value) = entry?;
        let state: DepositTreeState = decode_canonical(value.value())?;
        ensure!(key.value() == DepositTreeKey(network, user, state.anchor.chain_index), "deposit tree key differs from encoded chain");
        state.validate().map_err(|error| anyhow::anyhow!(error))?;
        deposit_tree_states.push(state);
    }
    Ok(deposit_tree_states)
}

fn load_changed_deposit_tree_states(tx: &redb::WriteTransaction, network: u64, user: u64, requested: &[DepositTreeState]) -> anyhow::Result<Vec<DepositTreeState>> {
    let table = tx.open_table(DEPOSIT_TREE_STATES)?;
    requested.iter().map(|state| {
        let row = table.get(DepositTreeKey(network, user, state.anchor.chain_index))?.context("included deposit-tree state missing")?;
        let saved: DepositTreeState = decode_canonical(row.value())?;
        saved.validate().map_err(|error| anyhow::anyhow!(error))?;
        Ok(saved)
    }).collect()
}

fn write_deposit_tree_states(tx: &redb::WriteTransaction, network: u64, user: u64, deposit_tree_states: &[DepositTreeState]) -> anyhow::Result<()> {
    let mut table = tx.open_table(DEPOSIT_TREE_STATES)?;
    for state in deposit_tree_states {
        state.validate().map_err(|error| anyhow::anyhow!(error))?;
        let bytes = encode_canonical(state)?;
        table.insert(DepositTreeKey(network, user, state.anchor.chain_index), bytes.as_slice())?;
    }
    Ok(())
}

fn write_batch_indexes(tx: &redb::WriteTransaction, session: &GuardianSession) -> anyhow::Result<()> {
    let mut burns = tx.open_table(INCLUDED_WITHDRAWAL_BURNS)?;
    let mut nonces = tx.open_table(WITHDRAWAL_NONCE)?;
    for append in &session.withdrawal_appends {
        let burn = &append.burn;
        burns.insert(WithdrawalBurnKey(session.network_magic, session.user_id, burn.sender_user_id, burn.token_contract_id, burn.nonce), session.nonce)?;
        nonces.insert(NonceKey(session.network_magic, session.user_id, append.chain_index, burn.nonce), session.nonce)?;
    }
    Ok(())
}

fn halt_account(accounts: &mut redb::Table<(u64, u64), &[u8]>, account: &GuardianAccount, reason: HaltReason) -> anyhow::Result<()> {
    let mut halted = account.clone();
    halted.state = guardian_common::protocol::GuardianAccountState::Halted;
    halted.halt_reason = Some(reason);
    halted.validate().map_err(|error| anyhow::anyhow!(error))?;
    let bytes = encode_canonical(&halted)?;
    accounts.insert((halted.network_magic, halted.user_id), bytes.as_slice())?;
    Ok(())
}
fn fresh_account(session: &GuardianSession, identity: protocol::Hash4, checkpoint_id: u64, checkpoint_hash: protocol::Hash4) -> GuardianAccount {
    GuardianAccount {
        network_magic: session.network_magic, user_id: session.user_id, state: guardian_common::protocol::GuardianAccountState::Active,
        last_checkpoint_id: checkpoint_id, last_checkpoint_hash: checkpoint_hash, imported_nonce: None,
        account_public_key: identity, imported_ending_leaf: None, withdrawal_chains: Vec::new(), halt_reason: None,
    }
}

pub(crate) async fn prove_pending_request(
    wallet: &mut psy_prover::session::WalletSession,
    client: &GuardianClient,
    archive: &RelayerDb,
    config: &protocol::GuardianConfig,
    request_json: &JsonText<GuardianSignRequest>,
    deposit_tree_states: &[DepositTreeState],
) -> anyhow::Result<Vec<u8>> {
    use psy_prover::trace::{TraceStep, TraceSignCircuitSource};
    use psy_vm::ups::multisig::MultisigSignatureWitness;
    let request = request_json.decode()?;
    request.validate_authorization(config)?;
    let trace = request.decode_trace()?;
    let witness = match trace.steps.last() {
        Some(TraceStep::ZkSign(step)) if matches!(step.sign_circuit_source, TraceSignCircuitSource::Multisig) => serde_json::from_slice::<MultisigSignatureWitness>(&step.sign_witness)?,
        _ => anyhow::bail!("guardian request is not a multisig trace"),
    };
    let (policy, _) = witness.policies()?;
    archive.save_request(config, request_json, deposit_tree_states, &[])?;
    let signatures = match archive.signatures(request.session_nonce)? {
        Some(signatures) => signatures,
        None if request.operation == protocol::GuardianOperation::Bridge => {
            let signatures = client.collect(request_json, &policy, trace.finalization.sig_hash).await?;
            archive.save_signatures(request.session_nonce, &signatures)?;
            signatures
        }
        None => anyhow::bail!("local operator signatures are required for the frozen policy request"),
    };
    validate_policy_signatures(&signatures, &policy, trace.finalization.sig_hash)?;
    wallet.inject_multisig_signatures(trace.meta.public_key, signatures).await?;
    if let Some(proof) = archive.proof(request.session_nonce)? {
        crate::guardian::verify::verify_cached_endcap_proof(wallet, &proof, &trace.finalization.submit_end_cap_input).await?;
        return Ok(proof);
    }
    let schedule = wallet.prepare_trace_proof_schedule(&trace).await?;
    let mut outputs = vec![wallet.prove_ups_start_job(trace.meta.public_key, &trace).await?];
    for seed in &schedule.seeds {
        outputs.push(wallet.prove_cfc_job_with_seed(trace.meta.public_key, &trace, seed).await?);
    }
    outputs.push(wallet.prove_zksign_job(trace.meta.public_key, &trace).await?);
    let output = wallet.prove_endcap_job_from_outputs(trace.meta.public_key, &trace, &schedule, outputs).await?;
    let proof = match output {
        psy_prover::session::TraceProofJobOutput::EndCap { proof, .. } => proof,
        _ => anyhow::bail!("EndCap proving returned another proof kind"),
    };
    archive.save_proof(request.session_nonce, &proof)?;
    Ok(proof)
}
#[cfg(test)]
pub(crate) fn tests_db() -> (std::path::PathBuf, RelayerDb) { tests::fresh() }

#[cfg(test)]
mod tests {
    use std::future::Future;
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn fixture_config() -> protocol::GuardianConfig { crate::guardian::test_fixture::codec_guardian_config() }

    /// Owner-only root whose every ancestor satisfies `protected_file_at`:
    /// directory, uid 0 or the effective uid, and no group/other write.
    /// `/tmp` is `01777`, so a fixture there is rejected as `KeyUnavailable`.
    fn protected_root(label: &str) -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).unwrap_or_else(|| home::home_dir().expect("home directory"));
        loop {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = base.join(format!("relayer-db-{label}-{}-{n}.dir", std::process::id()));
            match std::fs::DirBuilder::new().mode(0o700).create(&root) {
                Ok(()) => {
                    std::fs::DirBuilder::new().mode(0o700).create(root.join("db")).unwrap();
                    return root;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("protected fixture root: {error}"),
            }
        }
    }

    pub(super) fn fresh() -> (std::path::PathBuf, RelayerDb) {
        let root = protected_root("fresh");
        let db = RelayerDb::open(&root).unwrap();
        (root, db)
    }


    fn signatures() -> MultisigSignatures {
        MultisigSignatures { member_indices: vec![0, 2], signatures: vec![PsyCompressedSecp256K1Signature { public_key: [2; 33], signature: [1; 64], message: Hash256([0; 32]) }; 2] }
    }

    // These are persistence-boundary fixtures: production authenticates inclusion in
    // recover_guardian_inclusion before import_verified; no proof verifier runs here.
    fn import_request(nonce: u64, start: protocol::Hash4, end: protocol::Hash4) -> GuardianSignRequest {
        let mut request = crate::guardian::test_fixture::codec_request_fixture();
        let mut trace = request.decode_trace().unwrap();
        request.session_nonce = nonce;
        trace.finalization.nonce = GoldilocksField(nonce);
        trace.finalization.submit_end_cap_input.core.state_transition.start_user_leaf_hash = start;
        trace.finalization.submit_end_cap_input.core.state_transition.end_user_leaf_hash = end;
        let call_data = request.trace_json.decode().unwrap().call_data;
        request.trace_json = JsonText::from_value(&psy_prover::trace::GeneratedTxTraceJson::from_trace(&trace, call_data).unwrap()).unwrap();
        request.validate_authorization(&fixture_config()).unwrap();
        request
    }

    #[test]
    fn retained_stages_only_advance_with_immutable_payloads() {
        let (path, db) = fresh();
        let frozen = JsonText::from_value(&crate::guardian::test_fixture::codec_request_fixture()).unwrap();
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        let request = db.row(1).unwrap().unwrap();
        db.save_signatures(1, &signatures()).unwrap();
        let signed = db.row(1).unwrap().unwrap();
        assert!(db.retain(1, &request).is_err());
        assert!(db.retain(2, &signed).is_err());
        let mut changed = signed.clone();
        if let Request::Signed { request, .. } = &mut changed { request.push(' '); }
        assert!(db.retain(1, &changed).is_err());
        db.save_proof(1, &[0xAA]).unwrap();
        let proved = db.row(1).unwrap().unwrap();
        db.retain(1, &proved).unwrap();
        assert!(db.retain(1, &signed).is_err());
        let mut changed = proved.clone();
        if let Request::Proved { endcap, .. } = &mut changed { endcap[0] ^= 1; }
        assert!(db.retain(1, &changed).is_err());
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        db.save_signatures(1, &signatures()).unwrap();
        db.save_proof(1, &[0xAA]).unwrap();
        assert!(matches!(db.row(1).unwrap(), Some(Request::Proved { .. })));
        assert_eq!(db.proof(1).unwrap(), Some(vec![0xAA]));
        drop(db);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn exclusive_open_keeps_authorization_and_rejects_empty_or_partial() {
        let (root, db) = fresh();
        let relayer = root.join("db").join("relayer.redb");
        let second = std::fs::OpenOptions::new().read(true).write(true).open(&relayer).unwrap();
        assert!(matches!(redb::Database::builder().create_file(second).unwrap_err(), redb::DatabaseError::DatabaseAlreadyOpen));
        assert!(!root.with_file_name("account.lock").exists());
        let tx = db.db.begin_read().unwrap();
        let names = tx.list_tables().unwrap().map(|table| table.name().to_owned()).collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names, RELAYER_TABLES.into_iter().map(str::to_owned).collect());
        drop(tx);
        drop(db);
        let empty = protected_root("empty");
        std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(empty.join("db").join("relayer.redb")).unwrap();
        assert!(RelayerDb::open(&empty).is_err());
        let partial = protected_root("partial");
        let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(partial.join("db").join("relayer.redb")).unwrap();

        let raw = redb::Database::builder().create_file(file).unwrap();
        let tx = raw.begin_write().unwrap();
        tx.open_table(redb::TableDefinition::<(), &[u8]>::new("guardian_authorization_index")).unwrap();
        tx.commit().unwrap();
        drop(raw);
        assert!(RelayerDb::open(&partial).is_err());
        let inspect = redb::Database::builder().create_file(std::fs::OpenOptions::new().read(true).write(true).open(partial.join("db").join("relayer.redb")).unwrap()).unwrap();
        assert!(inspect.begin_read().unwrap().open_table(RELAYER_REQUEST).is_err());
        for path in [root, empty, partial] { let _ = std::fs::remove_dir_all(path); }
    }
    #[test]
    fn changed_account_refuses_stored_progress_and_leaves_rows_untouched() {
        let (root, db) = fresh();
        let request = crate::guardian::test_fixture::codec_request_fixture();
        db.save_request(&fixture_config(), &JsonText::from_value(&request).unwrap(), &[], &[]).unwrap();
        let prior_batch = FinalizationBatch { pending_finalization_range: Some(FinalizationRange { from_checkpoint: 1, to_checkpoint: 2 }), finalized_chains: BTreeSet::from([1]) };
        db.save_finalization_batch(&fixture_config(), &prior_batch).unwrap();
        drop(db);
        let mut changed = fixture_config();
        changed.network.guardian_initial_member_hashes.as_mut().unwrap().swap(0, 1);
        let changed_db = RelayerDb::open(&root).unwrap();
        assert!(changed_db.finalization_batch(&changed).is_err());
        assert!(changed_db.chain_claims(&changed).is_err());
        let next_batch = FinalizationBatch { pending_finalization_range: None, finalized_chains: BTreeSet::new() };
        assert!(changed_db.save_finalization_batch(&changed, &next_batch).is_err());
        assert!(changed_db.save_chain_claims(&changed, 1, &ChainClaims::default()).is_err());
        assert!(changed_db.save_finalization_and_claims(&changed, &next_batch, &[]).is_err());
        assert!(changed_db.save_claims_and_batch(&changed, &BTreeMap::new(), &next_batch).is_err());
        drop(changed_db);
        let original = RelayerDb::open(&root).unwrap();
        assert_eq!(original.finalization_batch(&fixture_config()).unwrap(), prior_batch);
        assert!(original.chain_claims(&fixture_config()).unwrap().is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn open_rejects_missing_table_and_never_recreates_it() {
        let (root, db) = fresh();
        let tx = db.db.begin_read().unwrap();
        let before = tx.list_tables().unwrap().map(|table| table.name().to_owned()).collect::<std::collections::BTreeSet<_>>();
        drop(tx);
        drop(db);
        assert_eq!(before, RELAYER_TABLES.into_iter().map(str::to_owned).collect());
        {
            let file = std::fs::OpenOptions::new().read(true).write(true).open(root.join("db").join("relayer.redb")).unwrap();
            let raw = redb::Database::builder().create_file(file).unwrap();
            let tx = raw.begin_write().unwrap();
            tx.delete_table(CHAIN_CLAIMS).unwrap();
            tx.commit().unwrap();
        }
        let error = RelayerDb::open(&root).err().expect("incomplete schema must be rejected");
        assert_eq!(error.to_string(), LEGACY_JOURNAL);
        let file = std::fs::OpenOptions::new().read(true).write(true).open(root.join("db").join("relayer.redb")).unwrap();
        let inspect = redb::Database::builder().create_file(file).unwrap();
        let names = inspect.begin_read().unwrap().list_tables().unwrap().map(|table| table.name().to_owned()).collect::<std::collections::BTreeSet<_>>();
        assert!(!names.contains(CHAIN_CLAIMS.name()));
        let mut expected = before;
        expected.remove(CHAIN_CLAIMS.name());
        assert_eq!(names, expected);
        std::fs::remove_dir_all(root).unwrap();
    }


    #[test]
    fn tail_request_is_contiguous_and_same_payload_does_not_overwrite() {
        let (path, db) = fresh();
        let request = crate::guardian::test_fixture::codec_request_fixture();
        let frozen = JsonText::from_value(&request).unwrap();
        let mut second = request.clone();
        second.session_nonce = 2;
        assert!(db.save_request(&fixture_config(), &JsonText::from_value(&second).unwrap(), &[], &[]).is_err());
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        let mut changed = request.clone();
        changed.session_nonce = 9;
        assert!(db.save_request(&fixture_config(), &JsonText::from_value(&changed).unwrap(), &[], &[]).is_err());
        assert!(db.save_request(&fixture_config(), &JsonText::from_value(&second).unwrap(), &[], &[]).is_err());
        assert_eq!(db.pending_request().unwrap().unwrap().as_str(), frozen.as_str());
        assert_eq!(db.load_session(1, request.request_id().unwrap()).unwrap().0.as_str(), frozen.as_str());
        drop(db);
        let reopened = RelayerDb::open(&path).unwrap();
        assert_eq!(reopened.load_session(1, request.request_id().unwrap()).unwrap().0.as_str(), frozen.as_str());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn signed_stage_is_atomic_and_request_bytes_stay_fixed() {
        let (path, db) = fresh();
        let request = crate::guardian::test_fixture::codec_request_fixture();
        let frozen = JsonText::from_value(&request).unwrap();
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        assert!(db.signatures(1).unwrap().is_none());
        let saved = signatures();
        db.save_signatures(1, &saved).unwrap();
        db.save_signatures(1, &saved).unwrap();
        let mut different = saved.clone();
        different.signatures[0].signature[0] ^= 1;
        assert!(db.save_signatures(1, &different).is_err());
        assert_eq!(db.signatures(1).unwrap().unwrap().member_indices, vec![0, 2]);
        assert_eq!(db.pending_request().unwrap().unwrap().as_str(), frozen.as_str());
        drop(db);
        let reopened = RelayerDb::open(&path).unwrap();
        assert_eq!(reopened.pending_request().unwrap().unwrap().as_str(), frozen.as_str());
        assert!(reopened.proof(1).unwrap().is_none());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn proved_then_included_is_terminal_and_the_next_nonce_is_exact() {
        let (path, db) = fresh();
        let request = import_request(1, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8));
        let frozen = JsonText::from_value(&request).unwrap();
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        let saved = signatures();
        db.save_signatures(1, &saved).unwrap();
        db.save_proof(1, &[0xAA]).unwrap();
        assert!(db.save_proof(1, &[0xBB]).is_err());
        let record = GuardianSessionRecord {
            request_json: frozen.clone(),
            signatures_json: JsonText::from_value(&saved).unwrap(),
            endcap_input_json: JsonText::from_value(&request.decode_trace().unwrap().finalization.submit_end_cap_input).unwrap(),
            endcap_proof_hex: "0xaa".to_owned(), included_checkpoint_id: 1, included_checkpoint_hash: QHashOut::from_values(1, 2, 3, 4),
        };
        let session = GuardianSession { network_magic: request.network_magic, user_id: request.user_id, nonce: 1, record: record.clone(), starting_leaf_hash: protocol::Hash4::ZERO, ending_leaf_hash: QHashOut::from_values(5, 6, 7, 8), withdrawal_appends: Vec::new() };
        db.import_verified(&fixture_config(), &session, &[], 1, record.included_checkpoint_hash).unwrap();
        db.import_verified(&fixture_config(), &session, &[], 1, record.included_checkpoint_hash).unwrap();
        assert_eq!(db.load_account(request.network_magic, request.user_id).unwrap().unwrap().imported_nonce, Some(1));
        assert!(db.pending_request().unwrap().is_none());
        assert_eq!(db.signatures(1).unwrap().unwrap().member_indices, vec![0, 2]);
        assert_eq!(db.proof(1).unwrap().unwrap(), b"\xaa");
        let page = db.sessions(0, 1).unwrap();
        assert_eq!(page.sessions.len(), 1);
        assert!(!page.has_more);
        let next = import_request(3, session.ending_leaf_hash, QHashOut::from_values(9, 9, 9, 9));
        assert!(db.save_request(&fixture_config(), &JsonText::from_value(&next).unwrap(), &[], &[]).is_err());
        assert!(db.sessions(1, 1).unwrap().sessions.is_empty());
        drop(db);
        let reopened = RelayerDb::open(&path).unwrap();
        assert!(reopened.pending_request().unwrap().is_none());
        assert_eq!(reopened.sessions(0, 64).unwrap().sessions.len(), 1);
        let mut conflict = session.clone();
        conflict.ending_leaf_hash = QHashOut::from_values(9, 9, 9, 9);
        assert!(reopened.import_verified(&fixture_config(), &conflict, &[], 1, record.included_checkpoint_hash).is_err());
        let halted = reopened.load_account(request.network_magic, request.user_id).unwrap().unwrap();
        assert_eq!(halted.state, guardian_common::protocol::GuardianAccountState::Halted);
        assert_eq!(halted.imported_nonce, Some(1));
        assert!(reopened.import_verified(&fixture_config(), &session, &[], 1, record.included_checkpoint_hash).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn included_nonce_admits_only_the_next_session() {
        let (path, db) = fresh();
        let request = import_request(1, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8));
        let frozen = JsonText::from_value(&request).unwrap();
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        let saved = signatures();
        db.save_signatures(1, &saved).unwrap();
        db.save_proof(1, &[0xAA]).unwrap();
        let record = GuardianSessionRecord {
            request_json: frozen.clone(),
            signatures_json: JsonText::from_value(&saved).unwrap(),
            endcap_input_json: JsonText::from_value(&request.decode_trace().unwrap().finalization.submit_end_cap_input).unwrap(),
            endcap_proof_hex: "0xaa".to_owned(), included_checkpoint_id: 1, included_checkpoint_hash: QHashOut::from_values(1, 2, 3, 4),
        };
        let session = GuardianSession { network_magic: request.network_magic, user_id: request.user_id, nonce: 1, record: record.clone(), starting_leaf_hash: protocol::Hash4::ZERO, ending_leaf_hash: QHashOut::from_values(5, 6, 7, 8), withdrawal_appends: Vec::new() };
        db.import_verified(&fixture_config(), &session, &[], 1, record.included_checkpoint_hash).unwrap();
        assert!(db.pending_request().unwrap().is_none());
        let next = import_request(2, session.ending_leaf_hash, QHashOut::from_values(9, 9, 9, 9));
        let next_frozen = JsonText::from_value(&next).unwrap();
        db.save_request(&fixture_config(), &next_frozen, &[], &[]).unwrap();
        assert_eq!(db.pending_request().unwrap().unwrap().as_str(), next_frozen.as_str());
        let skipped = import_request(3, session.ending_leaf_hash, QHashOut::from_values(9, 9, 9, 9));
        assert!(db.save_request(&fixture_config(), &JsonText::from_value(&skipped).unwrap(), &[], &[]).is_err());
        drop(db);
        let reopened = RelayerDb::open(&path).unwrap();
        assert_eq!(reopened.pending_request().unwrap().unwrap().as_str(), next_frozen.as_str());
        assert_eq!(reopened.load_account(request.network_magic, request.user_id).unwrap().unwrap().imported_nonce, Some(1));
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn pending_row_reopens_without_a_second_writer() {
        let (path, db) = fresh();
        let request = crate::guardian::test_fixture::codec_request_fixture();
        let frozen = JsonText::from_value(&request).unwrap();
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        assert!(RelayerDb::open(&path).is_err());
        assert_eq!(db.pending_request().unwrap().unwrap().as_str(), frozen.as_str());
        assert!(db.load_account(request.network_magic, request.user_id).unwrap().is_none());
        assert!(db.chain_claims(&fixture_config()).unwrap().is_empty());
        assert_eq!(db.finalization_batch(&fixture_config()).unwrap(), FinalizationBatch::default());
        drop(db);
        let reopened = RelayerDb::open(&path).unwrap();
        assert_eq!(reopened.pending_request().unwrap().unwrap().as_str(), frozen.as_str());
        let (saved_request, included) = reopened.load_session(1, request.request_id().unwrap()).unwrap();
        assert_eq!(saved_request.as_str(), frozen.as_str());
        assert!(included.is_none());
        assert!(reopened.load_account(request.network_magic, request.user_id).unwrap().is_none());
        assert!(reopened.chain_claims(&fixture_config()).unwrap().is_empty());
        assert_eq!(reopened.finalization_batch(&fixture_config()).unwrap(), FinalizationBatch::default());
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn included_and_claim_insert_failure_does_not_half_write() {
        use guardian_common::protocol::{GuardianOperation, WithdrawalAppendRecord, WithdrawalBurnRecord};
        let path = protected_root("poison-claims");
        let db = RelayerDb::open(&path).unwrap();
        let burn = WithdrawalBurnRecord { sender_user_id: 1, token_contract_id: 3, destination_chain_index: 0, token: [0, 0, 0, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b], amount: [0, 0, 0, 0, 0, 0, 0, 1], recipient: [0, 0, 0, 0x0c0c0c0c, 0x0c0c0c0c, 0x0c0c0c0c, 0x0c0c0c0c, 0x0c0c0c0c], nonce: [0; 8] };
        let mut request = import_request(1, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8));
        request.operation = GuardianOperation::Bridge;
        request.withdrawal_records = vec![burn.clone()];
        request.validate_authorization(&fixture_config()).unwrap();
        let frozen = JsonText::from_value(&request).unwrap();
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        {
            let tx = db.db.begin_write().unwrap();
            tx.open_table(CHAIN_CLAIMS).unwrap().insert(0u8, b"not-json".as_slice()).unwrap();
            tx.commit().unwrap();
        }
        let saved = signatures();
        let record = GuardianSessionRecord {
            request_json: frozen.clone(), signatures_json: JsonText::from_value(&saved).unwrap(),
            endcap_input_json: JsonText::from_value(&request.decode_trace().unwrap().finalization.submit_end_cap_input).unwrap(),
            endcap_proof_hex: "0xaa".to_owned(), included_checkpoint_id: 1, included_checkpoint_hash: QHashOut::from_values(1, 2, 3, 4),
        };
        let session = GuardianSession { network_magic: request.network_magic, user_id: request.user_id, nonce: 1, record, starting_leaf_hash: protocol::Hash4::ZERO, ending_leaf_hash: QHashOut::from_values(5, 6, 7, 8), withdrawal_appends: vec![WithdrawalAppendRecord { chain_index: 0, append_index: 0, burn: burn.clone() }] };
        assert!(db.import_verified(&fixture_config(), &session, &[], 1, session.record.included_checkpoint_hash).is_err());
        let inspect = |db: &RelayerDb| {
            assert_eq!(db.pending_request().unwrap().unwrap().as_str(), frozen.as_str());
            assert!(db.load_account(request.network_magic, request.user_id).unwrap().and_then(|account| account.imported_nonce).is_none());
            assert_eq!(db.inclusion_session_nonce(request.network_magic, request.user_id, 1, 3, burn.nonce).unwrap(), None);
            assert_eq!(db.nonce_inclusion_session(request.network_magic, request.user_id, 0, burn.nonce).unwrap(), None);
            assert!(db.sessions(0, 1).unwrap().sessions.is_empty());
            assert_eq!(db.finalization_batch(&fixture_config()).unwrap(), FinalizationBatch::default());
            assert!(db.chain_claims(&fixture_config()).is_err());
            let tx = db.db.begin_read().unwrap();
            assert_eq!(tx.open_table(CHAIN_CLAIMS).unwrap().get(0u8).unwrap().unwrap().value(), b"not-json");
        };
        inspect(&db);
        drop(db);
        inspect(&RelayerDb::open(&path).unwrap());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn quarantine_markers_persist_and_keep_the_first_reason() {
        let path = protected_root("quarantine");
        let db = RelayerDb::open(&path).unwrap();
        assert!(db.quarantined_withdrawals().unwrap().is_empty());
        let mut markers = BTreeMap::new();
        markers.insert((0u8, 33i64), WithdrawalQuarantine { reason: "WithdrawalMismatch".to_owned(), quarantined_at_unix: 100 });
        db.quarantine_withdrawals(&markers).unwrap();
        // A second write must not displace the original reason or timestamp.
        let mut repeat = BTreeMap::new();
        repeat.insert((0u8, 33i64), WithdrawalQuarantine { reason: "RewriteAttempt".to_owned(), quarantined_at_unix: 200 });
        repeat.insert((1u8, 34i64), WithdrawalQuarantine { reason: "WithdrawalMismatch".to_owned(), quarantined_at_unix: 300 });
        db.quarantine_withdrawals(&repeat).unwrap();
        let saved = db.quarantined_withdrawals().unwrap();
        assert_eq!(saved.len(), 2);
        assert_eq!(saved[&(0, 33)].reason, "WithdrawalMismatch");
        assert_eq!(saved[&(0, 33)].quarantined_at_unix, 100);
        assert_eq!(saved[&(1, 34)].reason, "WithdrawalMismatch");
        drop(db);
        let reopened = RelayerDb::open(&path).unwrap();
        assert_eq!(reopened.quarantined_withdrawals().unwrap(), saved);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn schema3_journal_migrates_by_adding_the_quarantine_table() {
        let path = protected_root("schema3");
        let db = RelayerDb::open(&path).unwrap();
        {
            // Regress the journal to the pre-quarantine schema 3 shape.
            let tx = db.db.begin_write().unwrap();
            tx.delete_table(WITHDRAWAL_QUARANTINE).unwrap();
            tx.open_table(JOURNAL_SCHEMA).unwrap().insert((), JOURNAL_SCHEMA_V3).unwrap();
            tx.commit().unwrap();
        }
        drop(db);
        let file = std::fs::OpenOptions::new().read(true).write(true).open(path.join("db").join("relayer.redb")).unwrap();
        let raw = redb::Database::builder().create_file(file).unwrap();
        assert_eq!(migrate_relayer_journal(&raw, &fixture_config()).unwrap(), 0);
        let schema = { let tx = raw.begin_read().unwrap(); tx.open_table(JOURNAL_SCHEMA).unwrap().get(()).unwrap().unwrap().value() };
        assert_eq!(schema, JOURNAL_SCHEMA_VERSION);
        drop(raw);
        let reopened = RelayerDb::open(&path).unwrap();
        assert!(reopened.quarantined_withdrawals().unwrap().is_empty());
        std::fs::remove_dir_all(path).unwrap();
    }



    /// Archives, signs, proves, and imports one chained session as an authenticated record.
    fn include_session(db: &RelayerDb, nonce: u64, start: protocol::Hash4, end: protocol::Hash4, checkpoint_id: u64, checkpoint_hash: protocol::Hash4) -> GuardianSession {
        let request = import_request(nonce, start, end);
        let frozen = JsonText::from_value(&request).unwrap();
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        let saved = signatures();
        db.save_signatures(nonce, &saved).unwrap();
        db.save_proof(nonce, &[0xAA]).unwrap();
        let record = GuardianSessionRecord {
            request_json: frozen.clone(),
            signatures_json: JsonText::from_value(&saved).unwrap(),
            endcap_input_json: JsonText::from_value(&request.decode_trace().unwrap().finalization.submit_end_cap_input).unwrap(),
            endcap_proof_hex: "0xaa".to_owned(), included_checkpoint_id: checkpoint_id, included_checkpoint_hash: checkpoint_hash,
        };
        let session = GuardianSession { network_magic: request.network_magic, user_id: request.user_id, nonce, record, starting_leaf_hash: start, ending_leaf_hash: end, withdrawal_appends: Vec::new() };
        db.import_verified(&fixture_config(), &session, &[], checkpoint_id, checkpoint_hash).unwrap();
        session
    }

    fn retained_keys(db: &RelayerDb) -> Vec<u64> {
        let tx = db.db.begin_read().unwrap();
        let table = tx.open_table(RELAYER_REQUEST).unwrap();
        table.iter().unwrap().map(|row| row.unwrap().0.value()).collect()
    }

    fn write_raw_request(db: &RelayerDb, nonce: u64, value: &Request) {
        let tx = db.db.begin_write().unwrap();
        tx.open_table(RELAYER_REQUEST).unwrap().insert(nonce, encode(value).unwrap().as_slice()).unwrap();
        tx.commit().unwrap();
    }

    fn remove_raw_request(db: &RelayerDb, nonce: u64) {
        let tx = db.db.begin_write().unwrap();
        tx.open_table(RELAYER_REQUEST).unwrap().remove(nonce).unwrap();
        tx.commit().unwrap();
    }

    fn write_raw_account(db: &RelayerDb, account: &GuardianAccount) {
        let tx = db.db.begin_write().unwrap();
        tx.open_table(GUARDIAN_ACCOUNT).unwrap().insert((account.network_magic, account.user_id), encode_canonical(account).unwrap().as_slice()).unwrap();
        tx.commit().unwrap();
    }

    fn fixture_account(session: &GuardianSession, checkpoint_id: u64, checkpoint_hash: protocol::Hash4) -> GuardianAccount {
        GuardianAccount {
            network_magic: session.network_magic, user_id: session.user_id,
            state: guardian_common::protocol::GuardianAccountState::Active,
            last_checkpoint_id: checkpoint_id, last_checkpoint_hash: checkpoint_hash,
            imported_nonce: Some(session.nonce), imported_ending_leaf: Some(session.ending_leaf_hash),
            account_public_key: fixture_config().account_public_key().unwrap(),
            withdrawal_chains: Vec::new(), halt_reason: None,
        }
    }

    #[test]
    fn import_prunes_older_rows_and_keeps_the_pending_successor() {
        let (path, db) = fresh();
        let s1 = include_session(&db, 1, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8), 1, QHashOut::from_values(1, 1, 1, 1));
        assert_eq!(retained_keys(&db), vec![1]);
        let s2 = include_session(&db, 2, s1.ending_leaf_hash, QHashOut::from_values(9, 9, 9, 9), 2, QHashOut::from_values(2, 2, 2, 2));
        assert_eq!(retained_keys(&db), vec![2]);
        let s3 = include_session(&db, 3, s2.ending_leaf_hash, QHashOut::from_values(1, 2, 3, 4), 3, QHashOut::from_values(3, 3, 3, 3));
        assert_eq!(retained_keys(&db), vec![3]);
        let next = import_request(4, s3.ending_leaf_hash, QHashOut::from_values(6, 6, 6, 6));
        let next_frozen = JsonText::from_value(&next).unwrap();
        db.save_request(&fixture_config(), &next_frozen, &[], &[]).unwrap();
        assert_eq!(retained_keys(&db), vec![3, 4]);
        assert!(matches!(db.row(3).unwrap(), Some(Request::Included { .. })));
        assert!(matches!(db.row(4).unwrap(), Some(Request::Request { .. })));
        assert_eq!(db.pending_request().unwrap().unwrap().as_str(), next_frozen.as_str());
        assert_eq!(db.load_account(next.network_magic, next.user_id).unwrap().unwrap().imported_nonce, Some(3));
        // Exact one behind recovers; an older gap serves the retained base without claiming contiguity.
        let behind = db.sessions(2, 1).unwrap();
        assert_eq!(behind.sessions.len(), 1);
        behind.validate_page(2, 1).unwrap();
        let gapped = db.sessions(0, 1).unwrap();
        assert_eq!(gapped.next_after_nonce, 3);
        gapped.validate_page(0, 1).unwrap();
        drop(db);
        let reopened = RelayerDb::open(&path).unwrap();
        assert_eq!(retained_keys(&reopened), vec![3, 4]);
        assert_eq!(reopened.pending_request().unwrap().unwrap().as_str(), next_frozen.as_str());
        assert!(reopened.load_session(1, next.request_id().unwrap()).is_err());
        // The marker-3 validator accepts the non-1 suffix with no schema bump.
        assert_eq!(migrate_relayer_journal(&reopened.db, &fixture_config()).unwrap(), 2);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn save_request_cannot_grow_a_row_below_or_beyond_the_account_cursor() {
        let (path, db) = fresh();
        let s1 = include_session(&db, 1, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8), 1, QHashOut::from_values(1, 1, 1, 1));
        let s2 = include_session(&db, 2, s1.ending_leaf_hash, QHashOut::from_values(9, 9, 9, 9), 2, QHashOut::from_values(2, 2, 2, 2));
        let s3 = include_session(&db, 3, s2.ending_leaf_hash, QHashOut::from_values(1, 2, 3, 4), 3, QHashOut::from_values(3, 3, 3, 3));
        assert_eq!(retained_keys(&db), vec![3]);
        // With cursor A = 3 a stale nonce 1 would have silently grown a row below the pruned suffix;
        // previous == 0 skips the previous-row check, so only the cursor check can stop it.
        let stale = import_request(1, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8));
        let error = db.save_request(&fixture_config(), &JsonText::from_value(&stale).unwrap(), &[], &[]).unwrap_err();
        assert_eq!(error.to_string(), "relayer request does not extend the imported account cursor");
        assert_eq!(retained_keys(&db), vec![3]);
        let next = import_request(4, s3.ending_leaf_hash, QHashOut::from_values(6, 6, 6, 6));
        db.save_request(&fixture_config(), &JsonText::from_value(&next).unwrap(), &[], &[]).unwrap();
        assert_eq!(retained_keys(&db), vec![3, 4]);
        let beyond = import_request(5, s3.ending_leaf_hash, QHashOut::from_values(6, 6, 6, 6));
        assert!(db.save_request(&fixture_config(), &JsonText::from_value(&beyond).unwrap(), &[], &[]).is_err());
        assert_eq!(retained_keys(&db), vec![3, 4]);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn transitional_full_history_stays_valid_until_the_next_import_prunes() {
        let (path, db) = fresh();
        let s1 = include_session(&db, 1, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8), 1, QHashOut::from_values(1, 1, 1, 1));
        let first = db.row(1).unwrap().unwrap();
        let s2 = include_session(&db, 2, s1.ending_leaf_hash, QHashOut::from_values(9, 9, 9, 9), 2, QHashOut::from_values(2, 2, 2, 2));
        let second = db.row(2).unwrap().unwrap();
        let s3 = include_session(&db, 3, s2.ending_leaf_hash, QHashOut::from_values(1, 2, 3, 4), 3, QHashOut::from_values(3, 3, 3, 3));
        // Rebuild the pre-retention journal: every Included row from nonce 1 is transitional data.
        write_raw_request(&db, 1, &first);
        write_raw_request(&db, 2, &second);
        let next = import_request(4, s3.ending_leaf_hash, QHashOut::from_values(6, 6, 6, 6));
        db.save_request(&fixture_config(), &JsonText::from_value(&next).unwrap(), &[], &[]).unwrap();
        assert_eq!(retained_keys(&db), vec![1, 2, 3, 4]);
        assert_eq!(migrate_relayer_journal(&db.db, &fixture_config()).unwrap(), 4);
        include_session(&db, 4, s3.ending_leaf_hash, QHashOut::from_values(6, 6, 6, 6), 4, QHashOut::from_values(4, 4, 4, 4));
        assert_eq!(retained_keys(&db), vec![4]);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn retained_suffix_gaps_and_missing_authority_fail_closed() {
        let (path, db) = fresh();
        let s1 = include_session(&db, 1, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8), 1, QHashOut::from_values(1, 1, 1, 1));
        let s2 = include_session(&db, 2, s1.ending_leaf_hash, QHashOut::from_values(9, 9, 9, 9), 2, QHashOut::from_values(2, 2, 2, 2));
        let s3 = include_session(&db, 3, s2.ending_leaf_hash, QHashOut::from_values(1, 2, 3, 4), 3, QHashOut::from_values(3, 3, 3, 3));
        let next = import_request(4, s3.ending_leaf_hash, QHashOut::from_values(6, 6, 6, 6));
        db.save_request(&fixture_config(), &JsonText::from_value(&next).unwrap(), &[], &[]).unwrap();
        let included3 = db.row(3).unwrap().unwrap();
        let pending4 = db.row(4).unwrap().unwrap();
        let account = fixture_account(&s3, 3, QHashOut::from_values(3, 3, 3, 3));
        let validate = |config: &protocol::GuardianConfig| migrate_relayer_journal(&db.db, config);
        assert_eq!(validate(&fixture_config()).unwrap(), 2);
        // Removing the pending successor alone stays valid.
        remove_raw_request(&db, 4);
        assert_eq!(validate(&fixture_config()).unwrap(), 1);
        write_raw_request(&db, 4, &pending4);
        // A gap inside the retained suffix.
        let sixth = import_request(6, s3.ending_leaf_hash, QHashOut::from_values(6, 6, 6, 6));
        write_raw_request(&db, 6, &Request::Request { request: JsonText::from_value(&sixth).unwrap().as_str().to_owned(), deposit_tree_states: Vec::new() });
        assert!(validate(&fixture_config()).is_err());
        remove_raw_request(&db, 6);
        // A second unresolved request.
        let fifth = import_request(5, s3.ending_leaf_hash, QHashOut::from_values(6, 6, 6, 6));
        write_raw_request(&db, 5, &Request::Request { request: JsonText::from_value(&fifth).unwrap().as_str().to_owned(), deposit_tree_states: Vec::new() });
        assert!(validate(&fixture_config()).is_err());
        remove_raw_request(&db, 5);
        // A nonce zero row.
        write_raw_request(&db, 0, &pending4);
        assert!(validate(&fixture_config()).is_err());
        remove_raw_request(&db, 0);
        // A future Included row the cursor has not reached.
        let future_record = GuardianSessionRecord {
            request_json: JsonText::from_value(&next).unwrap(),
            signatures_json: JsonText::from_value(&signatures()).unwrap(),
            endcap_input_json: JsonText::from_value(&next.decode_trace().unwrap().finalization.submit_end_cap_input).unwrap(),
            endcap_proof_hex: "0xaa".to_owned(), included_checkpoint_id: 4, included_checkpoint_hash: QHashOut::from_values(4, 4, 4, 4),
        };
        write_raw_request(&db, 4, &Request::Included { record: future_record });
        assert!(validate(&fixture_config()).is_err());
        write_raw_request(&db, 4, &pending4);
        // The account cursor must bind the retained Included checkpoint.
        let mut moved = account.clone();
        moved.last_checkpoint_hash = QHashOut::from_values(9, 9, 9, 9);
        write_raw_account(&db, &moved);
        assert!(validate(&fixture_config()).is_err());
        write_raw_account(&db, &account);
        // A journal with rows but no imported cursor.
        let mut fresh_cursor = account.clone();
        fresh_cursor.imported_nonce = None;
        fresh_cursor.imported_ending_leaf = None;
        write_raw_account(&db, &fresh_cursor);
        assert!(validate(&fixture_config()).is_err());
        write_raw_account(&db, &account);
        // Two account rows bind two different identities.
        let mut stranger = account.clone();
        stranger.user_id += 1;
        write_raw_account(&db, &stranger);
        assert!(validate(&fixture_config()).is_err());
        { let tx = db.db.begin_write().unwrap(); tx.open_table(GUARDIAN_ACCOUNT).unwrap().remove((stranger.network_magic, stranger.user_id)).unwrap(); tx.commit().unwrap(); }
        // A changed configuration identity is refused.
        let mut changed = fixture_config();
        changed.network.guardian_initial_member_hashes.as_mut().unwrap().swap(0, 1);
        assert!(validate(&changed).is_err());
        // A stray pending row above nonce 1 without any account cursor.
        let (stray_path, stray) = fresh();
        let skipped = import_request(2, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8));
        write_raw_request(&stray, 2, &Request::Request { request: JsonText::from_value(&skipped).unwrap().as_str().to_owned(), deposit_tree_states: Vec::new() });
        assert!(migrate_relayer_journal(&stray.db, &fixture_config()).is_err());
        drop(stray);
        std::fs::remove_dir_all(stray_path).unwrap();
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn aborted_import_does_not_prune_older_rows() {
        use guardian_common::protocol::{GuardianOperation, WithdrawalAppendRecord, WithdrawalBurnRecord};
        let (path, db) = fresh();
        let s1 = include_session(&db, 1, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8), 1, QHashOut::from_values(1, 1, 1, 1));
        let burn = WithdrawalBurnRecord { sender_user_id: 1, token_contract_id: 3, destination_chain_index: 0, token: [0, 0, 0, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b], amount: [0, 0, 0, 0, 0, 0, 0, 1], recipient: [0, 0, 0, 0x0c0c0c0c, 0x0c0c0c0c, 0x0c0c0c0c, 0x0c0c0c0c, 0x0c0c0c0c], nonce: [0; 8] };
        let mut request = import_request(2, s1.ending_leaf_hash, QHashOut::from_values(9, 9, 9, 9));
        request.operation = GuardianOperation::Bridge;
        request.withdrawal_records = vec![burn.clone()];
        request.validate_authorization(&fixture_config()).unwrap();
        let frozen = JsonText::from_value(&request).unwrap();
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        {
            let tx = db.db.begin_write().unwrap();
            tx.open_table(CHAIN_CLAIMS).unwrap().insert(0u8, b"not-json".as_slice()).unwrap();
            tx.commit().unwrap();
        }
        let record = GuardianSessionRecord {
            request_json: frozen.clone(), signatures_json: JsonText::from_value(&signatures()).unwrap(),
            endcap_input_json: JsonText::from_value(&request.decode_trace().unwrap().finalization.submit_end_cap_input).unwrap(),
            endcap_proof_hex: "0xaa".to_owned(), included_checkpoint_id: 2, included_checkpoint_hash: QHashOut::from_values(2, 2, 2, 2),
        };
        let session = GuardianSession { network_magic: request.network_magic, user_id: request.user_id, nonce: 2, record, starting_leaf_hash: s1.ending_leaf_hash, ending_leaf_hash: QHashOut::from_values(9, 9, 9, 9), withdrawal_appends: vec![WithdrawalAppendRecord { chain_index: 0, append_index: 0, burn: burn.clone() }] };
        assert!(db.import_verified(&fixture_config(), &session, &[], 2, QHashOut::from_values(2, 2, 2, 2)).is_err());
        // The aborted commit leaves every row and the cursor untouched.
        assert_eq!(retained_keys(&db), vec![1, 2]);
        assert!(matches!(db.row(1).unwrap(), Some(Request::Included { .. })));
        assert!(matches!(db.row(2).unwrap(), Some(Request::Request { .. })));
        assert_eq!(db.load_account(request.network_magic, request.user_id).unwrap().unwrap().imported_nonce, Some(1));
        assert_eq!(db.pending_request().unwrap().unwrap().as_str(), frozen.as_str());
        assert_eq!(db.sessions(0, 1).unwrap().sessions.len(), 1);
        let tx = db.db.begin_read().unwrap();
        assert_eq!(tx.open_table(CHAIN_CLAIMS).unwrap().get(0u8).unwrap().unwrap().value(), b"not-json");
        drop(tx);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn retained_latest_replay_is_idempotent_and_pruned_replay_is_refused_without_halt() {
        let (path, db) = fresh();
        let s1 = include_session(&db, 1, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8), 1, QHashOut::from_values(1, 1, 1, 1));
        let s2 = include_session(&db, 2, s1.ending_leaf_hash, QHashOut::from_values(9, 9, 9, 9), 2, QHashOut::from_values(2, 2, 2, 2));
        // Nonce 1 left with its import commit; the retained latest replay stays idempotent.
        assert_eq!(retained_keys(&db), vec![2]);
        db.import_verified(&fixture_config(), &s2, &[], 2, QHashOut::from_values(2, 2, 2, 2)).unwrap();
        let account = db.load_account(s2.network_magic, s2.user_id).unwrap().unwrap();
        assert_eq!(account.state, guardian_common::protocol::GuardianAccountState::Active);
        assert_eq!(account.imported_nonce, Some(2));
        // A replay of a pruned nonce can no longer be byte-checked: typed refusal, never a halt.
        let error = db.import_verified(&fixture_config(), &s1, &[], 1, QHashOut::from_values(1, 1, 1, 1)).unwrap_err();
        assert_typed(&error, GuardianSignError::SessionHistoryUnavailable);
        let refused = db.load_account(s2.network_magic, s2.user_id).unwrap().unwrap();
        assert_eq!(refused.state, guardian_common::protocol::GuardianAccountState::Active);
        assert_eq!(refused.halt_reason, None);
        assert_eq!(refused.imported_nonce, Some(2));
        std::fs::remove_dir_all(path).unwrap();
    }
    fn withdrawal_burn(sender: u32, nonce: u32) -> guardian_common::protocol::WithdrawalBurnRecord {
        guardian_common::protocol::WithdrawalBurnRecord {
            sender_user_id: sender, token_contract_id: 3, destination_chain_index: 0,
            token: [0, 0, 0, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b],
            amount: [0, 0, 0, 0, 0, 0, 0, 1],
            recipient: [0, 0, 0, 0x0c0c0c0c, 0x0c0c0c0c, 0x0c0c0c0c, 0x0c0c0c0c, 0x0c0c0c0c],
            nonce: [0, 0, 0, 0, 0, 0, 0, nonce],
        }
    }

    fn import_appends(db: &RelayerDb, nonce: u64, start: protocol::Hash4, end: protocol::Hash4, checkpoint_id: u64, checkpoint_hash: protocol::Hash4, first_index: u32, burns: Vec<guardian_common::protocol::WithdrawalBurnRecord>) -> GuardianSession {
        use guardian_common::protocol::{GuardianOperation, WithdrawalAppendRecord};
        let mut request = import_request(nonce, start, end);
        request.operation = GuardianOperation::Bridge;
        request.withdrawal_records = burns.clone();
        request.validate_authorization(&fixture_config()).unwrap();
        let frozen = JsonText::from_value(&request).unwrap();
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        let saved = signatures();
        db.save_signatures(nonce, &saved).unwrap();
        db.save_proof(nonce, &[0xAA]).unwrap();
        let record = GuardianSessionRecord {
            request_json: frozen, signatures_json: JsonText::from_value(&saved).unwrap(),
            endcap_input_json: JsonText::from_value(&request.decode_trace().unwrap().finalization.submit_end_cap_input).unwrap(),
            endcap_proof_hex: "0xaa".to_owned(), included_checkpoint_id: checkpoint_id, included_checkpoint_hash: checkpoint_hash,
        };
        let session = GuardianSession {
            network_magic: request.network_magic, user_id: request.user_id, nonce, record, starting_leaf_hash: start, ending_leaf_hash: end,
            withdrawal_appends: burns.into_iter().enumerate().map(|(index, burn)| WithdrawalAppendRecord { chain_index: burn.destination_chain_index, append_index: first_index + index as u32, burn }).collect(),
        };
        db.import_verified(&fixture_config(), &session, &[], checkpoint_id, checkpoint_hash).unwrap();
        session
    }

    #[test]
    fn duplicate_keys_record_latest_session_and_keep_distinct_append_indexes() {
        let (path, db) = fresh();
        let same = withdrawal_burn(1, 7);
        let other = withdrawal_burn(2, 7);
        let first = import_appends(&db, 1, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8), 1, QHashOut::from_values(1, 1, 1, 1), 0, vec![same.clone(), same.clone(), other.clone()]);
        let account = db.load_account(first.network_magic, first.user_id).unwrap().unwrap();
        assert_eq!(account.state, guardian_common::protocol::GuardianAccountState::Active);
        assert_eq!(account.withdrawal_chains[0].1, 3);
        assert_eq!(first.withdrawal_appends.iter().map(|append| append.append_index).collect::<Vec<_>>(), vec![0, 1, 2]);
        assert_eq!(db.inclusion_session_nonce(first.network_magic, first.user_id, 1, 3, same.nonce).unwrap(), Some(1));
        assert_eq!(db.inclusion_session_nonce(first.network_magic, first.user_id, 2, 3, other.nonce).unwrap(), Some(1));
        assert_eq!(db.nonce_inclusion_session(first.network_magic, first.user_id, 0, same.nonce).unwrap(), Some(1));
        let again = import_appends(&db, 2, first.ending_leaf_hash, QHashOut::from_values(9, 9, 9, 9), 2, QHashOut::from_values(2, 2, 2, 2), 3, vec![same.clone()]);
        assert_eq!(again.withdrawal_appends[0].append_index, 3);
        assert_eq!(db.inclusion_session_nonce(again.network_magic, again.user_id, 1, 3, same.nonce).unwrap(), Some(2));
        assert_eq!(db.inclusion_session_nonce(again.network_magic, again.user_id, 2, 3, other.nonce).unwrap(), Some(1));
        assert_eq!(db.nonce_inclusion_session(again.network_magic, again.user_id, 0, same.nonce).unwrap(), Some(2));
        assert_eq!(db.load_account(again.network_magic, again.user_id).unwrap().unwrap().withdrawal_chains[0].1, 4);
        let mut wrong = again.clone();
        wrong.nonce = 3;
        wrong.starting_leaf_hash = again.ending_leaf_hash;
        wrong.ending_leaf_hash = QHashOut::from_values(3, 3, 3, 3);
        wrong.record.included_checkpoint_id = 3;
        wrong.record.included_checkpoint_hash = QHashOut::from_values(3, 3, 3, 3);
        wrong.withdrawal_appends = vec![guardian_common::protocol::WithdrawalAppendRecord { chain_index: 0, append_index: 9, burn: same.clone() }];
        let mut request = import_request(3, wrong.starting_leaf_hash, wrong.ending_leaf_hash);
        request.operation = protocol::GuardianOperation::Bridge;
        request.withdrawal_records = vec![same.clone()];
        wrong.record.request_json = JsonText::from_value(&request).unwrap();
        db.save_request(&fixture_config(), &wrong.record.request_json, &[], &[]).unwrap();
        assert!(db.import_verified(&fixture_config(), &wrong, &[], 3, wrong.record.included_checkpoint_hash).is_err());
        let halted = db.load_account(again.network_magic, again.user_id).unwrap().unwrap();
        assert_eq!((halted.state, halted.imported_nonce, halted.withdrawal_chains[0].1), (guardian_common::protocol::GuardianAccountState::Halted, Some(2), 4));
        assert_eq!(db.inclusion_session_nonce(again.network_magic, again.user_id, 1, 3, same.nonce).unwrap(), Some(2));
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn staged_request_conflict_still_rejects_before_inclusion_metadata() {
        let (path, db) = fresh();
        let burn = withdrawal_burn(1, 7);
        let mut request = import_request(1, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8));
        request.operation = protocol::GuardianOperation::Bridge;
        request.withdrawal_records = vec![burn.clone()];
        let frozen = JsonText::from_value(&request).unwrap();
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        let mut changed = request.clone();
        changed.trace_json = JsonText::parse(format!(" {} ", changed.trace_json.as_str())).unwrap();
        let record = GuardianSessionRecord {
            request_json: JsonText::from_value(&changed).unwrap(), signatures_json: JsonText::from_value(&signatures()).unwrap(),
            endcap_input_json: JsonText::from_value(&request.decode_trace().unwrap().finalization.submit_end_cap_input).unwrap(),
            endcap_proof_hex: "0xaa".to_owned(), included_checkpoint_id: 1, included_checkpoint_hash: QHashOut::from_values(1, 1, 1, 1),
        };
        let session = GuardianSession {
            network_magic: request.network_magic, user_id: request.user_id, nonce: 1, record, starting_leaf_hash: protocol::Hash4::ZERO,
            ending_leaf_hash: QHashOut::from_values(5, 6, 7, 8),
            withdrawal_appends: vec![guardian_common::protocol::WithdrawalAppendRecord { chain_index: 0, append_index: 0, burn: burn.clone() }],
        };
        assert!(db.import_verified(&fixture_config(), &session, &[], 1, session.record.included_checkpoint_hash).is_err());
        assert!(db.load_account(request.network_magic, request.user_id).unwrap().and_then(|account| account.imported_nonce).is_none());
        assert_eq!(db.inclusion_session_nonce(request.network_magic, request.user_id, 1, 3, burn.nonce).unwrap(), None);
        assert_eq!(db.nonce_inclusion_session(request.network_magic, request.user_id, 0, burn.nonce).unwrap(), None);
        assert_eq!(db.pending_request().unwrap().unwrap().as_str(), frozen.as_str());
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn wrong_append_destination_rejects_without_advancing() {
        let (path, db) = fresh();
        let burn = withdrawal_burn(1, 7);
        let first = import_appends(&db, 1, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8), 1, QHashOut::from_values(1, 1, 1, 1), 0, vec![burn.clone()]);
        let saved = db.load_account(first.network_magic, first.user_id).unwrap().unwrap();
        let mut request = import_request(2, first.ending_leaf_hash, QHashOut::from_values(9, 9, 9, 9));
        request.operation = protocol::GuardianOperation::Bridge;
        request.withdrawal_records = vec![burn.clone()];
        let frozen = JsonText::from_value(&request).unwrap();
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        let saved_signatures = signatures();
        let record = GuardianSessionRecord {
            request_json: frozen.clone(), signatures_json: JsonText::from_value(&saved_signatures).unwrap(),
            endcap_input_json: JsonText::from_value(&request.decode_trace().unwrap().finalization.submit_end_cap_input).unwrap(),
            endcap_proof_hex: "0xaa".to_owned(), included_checkpoint_id: 2, included_checkpoint_hash: QHashOut::from_values(2, 2, 2, 2),
        };
        let session = GuardianSession {
            network_magic: request.network_magic, user_id: request.user_id, nonce: 2, record, starting_leaf_hash: first.ending_leaf_hash,
            ending_leaf_hash: QHashOut::from_values(9, 9, 9, 9),
            withdrawal_appends: vec![guardian_common::protocol::WithdrawalAppendRecord { chain_index: 1, append_index: 1, burn }],
        };
        assert!(db.import_verified(&fixture_config(), &session, &[], 2, session.record.included_checkpoint_hash).is_err());
        let account = db.load_account(first.network_magic, first.user_id).unwrap().unwrap();
        assert_eq!((account.state, account.imported_nonce, account.withdrawal_chains), (saved.state, saved.imported_nonce, saved.withdrawal_chains));
        assert_eq!(db.pending_request().unwrap().unwrap().as_str(), frozen.as_str());
        assert_eq!(db.inclusion_session_nonce(first.network_magic, first.user_id, 1, 3, session.withdrawal_appends[0].burn.nonce).unwrap(), Some(1));
        std::fs::remove_dir_all(path).unwrap();
    }



    #[test]
    fn conflicting_replays_of_the_retained_current_included_row_halt() {
        for label in ["request", "signatures", "proof"] {
            let path = protected_root(&format!("conflict-replay-{label}"));
            let db = RelayerDb::open(&path).unwrap();
            let session = include_session(&db, 1, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8), 1, QHashOut::from_values(1, 1, 1, 1));
            let mut record = session.record.clone();
            match label {
                "request" => { record.request_json = JsonText::from_value(&import_request(1, protocol::Hash4::ZERO, QHashOut::from_values(7, 7, 7, 7))).unwrap(); }
                "signatures" => { record.signatures_json = JsonText::from_value(&MultisigSignatures { member_indices: vec![0, 1], signatures: vec![signatures().signatures[0].clone(); 2] }).unwrap(); }
                "proof" => { record.endcap_proof_hex = "0xbb".to_owned(); }
                _ => unreachable!(),
            }
            let conflicting = GuardianSession { record, ..session.clone() };
            db.import_verified(&fixture_config(), &conflicting, &[], session.record.included_checkpoint_id, session.record.included_checkpoint_hash).unwrap_err();
            let halted = db.load_account(session.network_magic, session.user_id).unwrap().unwrap();
            assert_eq!(halted.state, guardian_common::protocol::GuardianAccountState::Halted);
            assert_eq!(halted.halt_reason, Some(HaltReason::NonceConsumedDifferently));
            // Each conflicting variant persists its halt in its own committed write transaction.
            drop(db);
            std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test]
    fn same_checkpoint_id_with_different_leaf_halts_checkpoint_conflict() {
        let (path, db) = fresh();
        let request = import_request(1, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8));
        let frozen = JsonText::from_value(&request).unwrap();
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        let saved = signatures();
        let record = GuardianSessionRecord {
            request_json: frozen.clone(),
            signatures_json: JsonText::from_value(&saved).unwrap(),
            endcap_input_json: JsonText::from_value(&request.decode_trace().unwrap().finalization.submit_end_cap_input).unwrap(),
            endcap_proof_hex: "0xaa".to_owned(), included_checkpoint_id: 1, included_checkpoint_hash: QHashOut::from_values(1, 2, 3, 4),
        };
        let session = GuardianSession { network_magic: request.network_magic, user_id: request.user_id, nonce: 1, record, starting_leaf_hash: protocol::Hash4::ZERO, ending_leaf_hash: QHashOut::from_values(5, 6, 7, 8), withdrawal_appends: Vec::new() };
        db.import_verified(&fixture_config(), &session, &[], 1, QHashOut::from_values(1, 2, 3, 4)).unwrap();
        // The next nonce binds the SAME checkpoint id to a different leaf.
        let next = import_request(2, session.ending_leaf_hash, QHashOut::from_values(6, 6, 6, 6));
        let next_frozen = JsonText::from_value(&next).unwrap();
        db.save_request(&fixture_config(), &next_frozen, &[], &[]).unwrap();
        let next_record = GuardianSessionRecord {
            request_json: next_frozen,
            signatures_json: JsonText::from_value(&saved).unwrap(),
            endcap_input_json: JsonText::from_value(&next.decode_trace().unwrap().finalization.submit_end_cap_input).unwrap(),
            endcap_proof_hex: "0xbb".to_owned(), included_checkpoint_id: 1, included_checkpoint_hash: QHashOut::from_values(9, 9, 9, 9),
        };
        let next_session = GuardianSession { network_magic: request.network_magic, user_id: request.user_id, nonce: 2, record: next_record, starting_leaf_hash: QHashOut::from_values(5, 6, 7, 8), ending_leaf_hash: QHashOut::from_values(6, 6, 6, 6), withdrawal_appends: Vec::new() };
        assert!(db.import_verified(&fixture_config(), &next_session, &[], 1, QHashOut::from_values(9, 9, 9, 9)).is_err());
        let halted = db.load_account(request.network_magic, request.user_id).unwrap().unwrap();
        assert_eq!(halted.state, guardian_common::protocol::GuardianAccountState::Halted);
        assert_eq!(halted.halt_reason, Some(HaltReason::CheckpointConflict));
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn collector_requires_two_distinct_authorized_signatures_on_same_message() {
        use plonky2::hash::poseidon::PoseidonPermutation;
        use psy_client_common::data::secp256k1::CompressedPublicKey;
        use psy_crypto::signature::secp256k1::wallet::{hash_no_pad_compressed_public_key, secp256k1_sign};
        let sighash = QHashOut::from_values(1, 2, 3, 4);
        let members: Vec<_> = (1u8..=3).map(|byte| {
            let signature = secp256k1_sign(k256::ecdsa::SigningKey::from_slice(&[byte; 32]).unwrap(), sighash).unwrap();
            let hash = hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(CompressedPublicKey(signature.public_key));
            (hash, signature)
        }).collect();
        let mut policy = MultisigPolicy { version: 1, threshold: 2, member_count: 3, member_hashes: [QHashOut::ZERO; 8] };
        for (index, member) in members.iter().enumerate() { policy.member_hashes[index] = member.0; }
        assert!(select_signatures(&mut [(0, members[0].1)], &policy, sighash).is_none());
        assert!(select_signatures(&mut [(0, members[0].1), (0, members[0].1)], &policy, sighash).is_none());
        assert!(select_signatures(&mut [(0, members[0].1), (1, members[2].1)], &policy, sighash).is_none());
        assert!(select_signatures(&mut [(0, members[0].1), (2, members[2].1)], &policy, QHashOut::from_values(4, 3, 2, 1)).is_none());
        let mut invalid = members[0].1;
        invalid.signature = [0; 64];
        let accepted = select_signatures(&mut [(0, invalid), (2, members[2].1), (0, members[0].1)], &policy, sighash).unwrap();
        assert_eq!(accepted.member_indices, vec![0, 2]);
        validate_policy_signatures(&accepted, &policy, sighash).unwrap();
    }
    fn drive<T>(future: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(future)
    }

    fn bridge_collect_request() -> GuardianSignRequest {
        let mut request = crate::guardian::test_fixture::codec_request_fixture();
        request.operation = protocol::GuardianOperation::Bridge;
        request.withdrawal_records = vec![protocol::WithdrawalBurnRecord { sender_user_id: 1, token_contract_id: 3, destination_chain_index: 0, token: [0, 0, 0, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b], amount: [0, 0, 0, 0, 0, 0, 0, 1], recipient: [0, 0, 0, 0x0c0c0c0c, 0x0c0c0c0c, 0x0c0c0c0c, 0x0c0c0c0c, 0x0c0c0c0c], nonce: [0; 8] }];
        request.validate().unwrap();
        request
    }

    fn authorized_signatures() -> (QHashOut<GoldilocksField>, MultisigPolicy, [PsyCompressedSecp256K1Signature; 3]) {
        use plonky2::hash::poseidon::PoseidonPermutation;
        use psy_client_common::data::secp256k1::CompressedPublicKey;
        use psy_crypto::signature::secp256k1::wallet::{hash_no_pad_compressed_public_key, secp256k1_sign};
        let sighash = QHashOut::from_values(1, 2, 3, 4);
        let members: Vec<_> = (1u8..=3).map(|byte| {
            let signature = secp256k1_sign(k256::ecdsa::SigningKey::from_slice(&[byte; 32]).unwrap(), sighash).unwrap();
            let hash = hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(CompressedPublicKey(signature.public_key));
            (hash, signature)
        }).collect();
        let mut policy = MultisigPolicy { version: 1, threshold: 2, member_count: 3, member_hashes: [QHashOut::ZERO; 8] };
        for (index, member) in members.iter().enumerate() { policy.member_hashes[index] = member.0; }
        (sighash, policy, [members[0].1, members[1].1, members[2].1])
    }

    fn signed_body(request: &GuardianSignRequest, policy: &MultisigPolicy, sighash: QHashOut<GoldilocksField>, member: u8, signature: PsyCompressedSecp256K1Signature) -> Vec<u8> {
        let response = GuardianSignResponse {
            request_id: request.request_id().unwrap(),
            network_magic: request.network_magic,
            user_id: request.user_id,
            session_nonce: request.session_nonce,
            policy_commitment: policy.commitment().unwrap(),
            member_index: member,
            message: protocol::Hex::<32>(Hash256::from(sighash).0),
            public_key: protocol::Hex(signature.public_key),
            signature: protocol::Hex(signature.signature),
        };
        serde_json::to_vec(&response).unwrap()
    }

    fn refusal_body(code: GuardianSignError) -> Vec<u8> {
        serde_json::to_vec(&GuardianSignErrorResponse::new(None, code)).unwrap()
    }

    fn serve_once(status: u16, body: Vec<u8>, delay: Duration) -> String { serve_typed(status, "application/json", body, delay) }

    fn serve_typed(status: u16, content_type: &'static str, body: Vec<u8>, delay: Duration) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 8192];
            let mut header_end = None;
            loop {
                if let Some(pos) = buf.windows(4).position(|mark| mark == b"\r\n\r\n") { header_end = Some(pos + 4); break; }
                if buf.len() > 65_536 { return; }
                let Ok(n) = stream.read(&mut tmp) else { return };
                if n == 0 { return; }
                buf.extend_from_slice(&tmp[..n]);
            }
            let header_end = header_end.unwrap();
            let headers = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
            let length = headers.lines().find_map(|line| line.strip_prefix("content-length:")).and_then(|value| value.trim().parse::<usize>().ok()).unwrap_or(0);
            while buf.len() < header_end.saturating_add(length) {
                let Ok(n) = stream.read(&mut tmp) else { return };
                if n == 0 { return; }
                buf.extend_from_slice(&tmp[..n]);
            }
            if !delay.is_zero() { std::thread::sleep(delay); }
            let head = format!("HTTP/1.1 {status} status\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        });
        format!("http://{addr}/")
    }

    fn refused_origin() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        format!("http://{addr}/")
    }

    fn assert_typed(error: &anyhow::Error, expected: GuardianSignError) {
        assert_eq!(error.downcast_ref::<GuardianSignError>(), Some(&expected), "{error:?}");
        assert_eq!(error.to_string(), expected.to_string());
    }

    #[test]
    fn quorum_succeeds_when_one_guardian_refuses() {
        let (sighash, policy, signatures) = authorized_signatures();
        let request = bridge_collect_request();
        let json = JsonText::from_value(&request).unwrap();
        let later = Duration::from_millis(300);
        let origins = [
            serve_once(GuardianSignError::AccountHalted.http_status(), refusal_body(GuardianSignError::AccountHalted), Duration::ZERO),
            serve_once(200, signed_body(&request, &policy, sighash, 0, signatures[0]), later),
            serve_once(200, signed_body(&request, &policy, sighash, 2, signatures[2]), later),
        ];
        let accepted = drive(async {
            GuardianClient::new(&origins).unwrap().collect(&json, &policy, sighash).await.unwrap()
        });
        assert_eq!(accepted.member_indices, vec![0, 2]);
        validate_policy_signatures(&accepted, &policy, sighash).unwrap();
    }

    #[test]
    fn collect_refuses_policy_before_any_network_request() {
        let (sighash, policy, _) = authorized_signatures();
        let mut request = crate::guardian::test_fixture::codec_request_fixture();
        request.operation = protocol::GuardianOperation::ReplacePolicy;
        let json = JsonText::from_value(&request).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origins = [format!("http://{}/", listener.local_addr().unwrap()), refused_origin(), refused_origin()];
        let error = drive(async { GuardianClient::new(&origins).unwrap().collect(&json, &policy, sighash).await.unwrap_err() });
        drop(listener);
        assert!(error.to_string().contains("explicit local operator approval"), "{error:?}");
    }

    #[test]
    fn transport_and_retryable_failures_are_signature_quorum_unavailable() {
        let (sighash, policy, _) = authorized_signatures();
        let request = bridge_collect_request();
        let json = JsonText::from_value(&request).unwrap();
        let missing = [refused_origin(), refused_origin(), refused_origin()];
        let error = drive(async {
            GuardianClient::new(&missing).unwrap().collect(&json, &policy, sighash).await.unwrap_err()
        });
        assert_typed(&error, GuardianSignError::SignatureQuorumUnavailable);
        let soft = GuardianSignError::DatabaseUnavailable;
        let origins = [
            serve_once(soft.http_status(), refusal_body(soft), Duration::ZERO),
            serve_once(soft.http_status(), refusal_body(soft), Duration::ZERO),
            serve_once(soft.http_status(), refusal_body(soft), Duration::ZERO),
        ];
        let error = drive(async {
            GuardianClient::new(&origins).unwrap().collect(&json, &policy, sighash).await.unwrap_err()
        });
        assert_typed(&error, GuardianSignError::SignatureQuorumUnavailable);
    }

    #[test]
    fn halt_without_quorum_is_typed_and_response_body_is_not_logged() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        const SECRET: &str = "SECRET_GUARDIAN_RESPONSE_BODY";
        struct LogCapture(Arc<Mutex<Vec<u8>>>);
        impl Write for LogCapture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { self.0.lock().expect("log").write(buf) }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        let (sighash, policy, signatures) = authorized_signatures();
        let request = bridge_collect_request();
        let json = JsonText::from_value(&request).unwrap();
        let mut halt_id = [0u8; 32];
        halt_id[..4].copy_from_slice(&0xdeadbeefu32.to_be_bytes());
        let halt = serde_json::to_vec(&GuardianSignErrorResponse::new(Some(protocol::Hex::<32>(halt_id)), GuardianSignError::AccountHalted)).unwrap();
        assert!(std::str::from_utf8(&halt).unwrap().contains("deadbeef"));
        let origins = [
            serve_once(GuardianSignError::AccountHalted.http_status(), halt, Duration::ZERO),
            serve_once(200, signed_body(&request, &policy, sighash, 0, signatures[0]), Duration::ZERO),
            serve_once(500, SECRET.as_bytes().to_vec(), Duration::ZERO),
        ];
        let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).without_time().with_ansi(false)
            .with_writer(move || LogCapture(writer.clone())).finish();
        let error = tracing::subscriber::with_default(subscriber, || drive(async {
            GuardianClient::new(&origins).unwrap().collect(&json, &policy, sighash).await.unwrap_err()
        }));
        let logged = String::from_utf8(captured.lock().expect("log").clone()).unwrap();
        assert!(!logged.contains(SECRET), "{logged}");
        assert!(!logged.contains("deadbeef"), "{logged}");
        assert_typed(&error, GuardianSignError::AccountHalted);
        assert!(!format!("{error:?}").contains(SECRET));
        assert!(!format!("{error:?}").contains("deadbeef"));
    }
    fn claim_words(chain: u8, nonce: u32) -> crate::bridge::propose_withdrawals::PendingWithdrawal {
        let token = [0, 0, 0, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b];
        let recipient = [0, 0, 0, 0x0c0c0c0c, 0x0c0c0c0c, 0x0c0c0c0c, 0x0c0c0c0c, 0x0c0c0c0c];
        let mut nonce_words = [0; 8];
        nonce_words[7] = nonce;
        let leaf_hash = crate::bridge::propose_withdrawals::compute_withdrawal_leaf_hash(1, recipient, token, [0, 0, 0, 0, 0, 0, 0, 1], nonce_words, u64::from(chain), 3).unwrap();
        crate::bridge::propose_withdrawals::PendingWithdrawal {
            event_id: i64::from(nonce), checkpoint_id: 4, user_id: 1, sender_user_id: 1, contract_id: 3,
            destination_chain_index: u64::from(chain), token_address: token, amount: [0, 0, 0, 0, 0, 0, 0, 1],
            recipient, nonce: nonce_words, leaf_hash,
        }
    }

    #[test]
    fn progress_codec_rejects_unknown_missing_and_noncanonical_fields() {
        let withdrawal = claim_words(2, 1);
        let claims = ChainClaims {
            pending_claim_withdrawals: BTreeMap::from([(withdrawal.leaf_hash.clone(), withdrawal)]),
            ..ChainClaims::default()
        };
        let encoded = encode_progress(&claims).unwrap();
        assert_eq!(decode_progress::<ChainClaims>(&encoded).unwrap(), claims);
        let text = String::from_utf8(encoded).unwrap();
        for invalid in [
            "not-json".to_owned(),
            "{}".to_owned(),
            format!(" {text}"),
            text.replacen('{', "{\"unknown\":0,", 1),
            text.replacen("\"event_id\":", "\"unknown\":0,\"event_id\":", 1),
            text.replacen("\"event_id\":1", "\"event_id\":1,\"event_id\":1", 1),
        ] {
            assert!(decode_progress::<ChainClaims>(invalid.as_bytes()).is_err(), "{invalid}");
        }
        let batch = FinalizationBatch {
            pending_finalization_range: Some(FinalizationRange { from_checkpoint: 1, to_checkpoint: u64::MAX }),
            finalized_chains: BTreeSet::from([9, 2]),
        };
        assert_eq!(decode_progress::<FinalizationBatch>(&encode_progress(&batch).unwrap()).unwrap(), batch);
        assert!(decode_progress::<FinalizationBatch>(br#"{"pending_finalization_range":null,"finalized_chains":[9,2]}"#).is_err());
        assert!(decode_progress::<FinalizationBatch>(br#"{"finalized_chains":[]}"#).is_err());
    }

    #[test]
    fn progress_rows_round_trip_in_leaf_order_not_insertion_order() {
        let (path, db) = fresh();
        db.save_request(&fixture_config(), &JsonText::from_value(&crate::guardian::test_fixture::codec_request_fixture()).unwrap(), &[], &[]).unwrap();
        let first = claim_words(2, 1);
        let second = claim_words(2, 2);
        let (smaller, larger) = if first.leaf_hash < second.leaf_hash { (first, second) } else { (second, first) };
        let mut pending = BTreeMap::new();
        pending.insert(larger.leaf_hash.clone(), larger.clone());
        pending.insert(smaller.leaf_hash.clone(), smaller.clone());
        let mut retired = BTreeMap::new();
        retired.insert(larger.leaf_hash.clone(), crate::bridge::claim_attempts::RetiredClaim { withdrawal: larger.clone(), attempts: 3, last_reason: "bridge rejected".into(), retired_at_unix: 9 });
        let claims = ChainClaims {
            pending_claim_withdrawals: pending,
            claim_retry: BTreeMap::from([(smaller.leaf_hash.clone(), crate::bridge::claim_attempts::ClaimAttempts { attempts: 2, last_reason: "proof late".into(), hold: crate::bridge::claim_attempts::ClaimHold::None })]),
            retired_claim_withdrawals: retired,
        };
        db.save_chain_claims(&fixture_config(), 2, &claims).unwrap();
        let raw = {
            let tx = db.db.begin_read().unwrap();
            tx.open_table(CHAIN_CLAIMS).unwrap().get(2u8).unwrap().unwrap().value().to_vec()
        };
        let again = serde_json::to_vec(&claims).unwrap();
        assert_eq!(raw, again);
        assert!(raw.windows(smaller.leaf_hash.len()).position(|window| window == smaller.leaf_hash.as_bytes()).unwrap()
            < raw.windows(larger.leaf_hash.len()).position(|window| window == larger.leaf_hash.as_bytes()).unwrap());
        assert_eq!(db.chain_claims(&fixture_config()).unwrap(), BTreeMap::from([(2, claims)]));
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn request_and_claims_fail_together_when_the_claim_row_is_poisoned() {
        let (path, db) = fresh();
        let request = crate::guardian::test_fixture::codec_request_fixture();
        let frozen = JsonText::from_value(&request).unwrap();
        {
            let tx = db.db.begin_write().unwrap();
            tx.open_table(CHAIN_CLAIMS).unwrap().insert(2u8, b"not-json".as_slice()).unwrap();
            tx.commit().unwrap();
        }
        assert!(db.save_request(&fixture_config(), &frozen, &[], &[claim_words(2, 1)]).is_err());
        assert!(db.pending_request().unwrap().is_none());
        assert!(db.chain_claims(&fixture_config()).is_err());
        let tx = db.db.begin_read().unwrap();
        assert_eq!(tx.open_table(CHAIN_CLAIMS).unwrap().get(2u8).unwrap().unwrap().value(), b"not-json");
        drop(tx);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn shared_batch_and_every_chain_row_commit_or_stay_put() {
        let (path, db) = fresh();
        db.save_request(&fixture_config(), &JsonText::from_value(&crate::guardian::test_fixture::codec_request_fixture()).unwrap(), &[], &[]).unwrap();
        let kept = claim_words(1, 7);
        let mut prior = ChainClaims::default();
        prior.pending_claim_withdrawals.insert(kept.leaf_hash.clone(), kept.clone());
        db.save_chain_claims(&fixture_config(), 1, &prior).unwrap();
        db.save_chain_claims(&fixture_config(), 4, &ChainClaims::default()).unwrap();
        let prior_batch = FinalizationBatch { pending_finalization_range: Some(FinalizationRange { from_checkpoint: 1, to_checkpoint: 2 }), finalized_chains: BTreeSet::from([1]) };
        db.save_finalization_batch(&fixture_config(), &prior_batch).unwrap();
        let mut poisoned = BTreeMap::new();
        poisoned.insert(1, prior.clone());
        {
            let tx = db.db.begin_write().unwrap();
            tx.open_table(CHAIN_CLAIMS).unwrap().insert(9u8, b"not-json".as_slice()).unwrap();
            tx.commit().unwrap();
        }
        assert!(db.save_claims_and_batch(&fixture_config(), &poisoned, &FinalizationBatch { pending_finalization_range: Some(FinalizationRange { from_checkpoint: 8, to_checkpoint: 9 }), finalized_chains: BTreeSet::from([1, 4]) }).is_err());
        assert_eq!(db.finalization_batch(&fixture_config()).unwrap(), prior_batch);
        let tx = db.db.begin_read().unwrap();
        let table = tx.open_table(CHAIN_CLAIMS).unwrap();
        assert_eq!(table.get(1u8).unwrap().unwrap().value(), serde_json::to_vec(&prior).unwrap());
        assert_eq!(table.get(4u8).unwrap().unwrap().value(), serde_json::to_vec(&ChainClaims::default()).unwrap());
        assert_eq!(table.get(9u8).unwrap().unwrap().value(), b"not-json");
        drop(tx);
        {
            let tx = db.db.begin_write().unwrap();
            tx.open_table(CHAIN_CLAIMS).unwrap().remove(9u8).unwrap();
            tx.commit().unwrap();
        }
        let replacement = claim_words(1, 8);
        let mut next = ChainClaims::default();
        next.pending_claim_withdrawals.insert(replacement.leaf_hash.clone(), replacement);
        let next_batch = FinalizationBatch { pending_finalization_range: None, finalized_chains: BTreeSet::new() };
        db.save_claims_and_batch(&fixture_config(), &BTreeMap::from([(1, next.clone()), (9, ChainClaims::default())]), &next_batch).unwrap();
        let saved = db.chain_claims(&fixture_config()).unwrap();
        assert_eq!(saved[&1], next);
        assert_eq!(saved[&4], ChainClaims::default());
        assert!(saved[&9].pending_claim_withdrawals.is_empty());
        assert_eq!(db.finalization_batch(&fixture_config()).unwrap(), next_batch);
        std::fs::remove_dir_all(path).unwrap();
    }


    #[test]
    fn hard_refusal_follows_guardian_id_not_arrival() {
        let (sighash, policy, _) = authorized_signatures();
        let request = bridge_collect_request();
        let json = JsonText::from_value(&request).unwrap();
        let origins = [
            serve_once(GuardianSignError::ProofMismatch.http_status(), refusal_body(GuardianSignError::ProofMismatch), Duration::from_millis(400)),
            refused_origin(),
            serve_once(GuardianSignError::AccountHalted.http_status(), refusal_body(GuardianSignError::AccountHalted), Duration::ZERO),
        ];
        let error = drive(async {
            GuardianClient::new(&origins).unwrap().collect(&json, &policy, sighash).await.unwrap_err()
        });
        assert_typed(&error, GuardianSignError::ProofMismatch);
    }

    #[test]
    fn pruned_first_origin_without_a_later_record_returns_none() {
        let mut request = crate::guardian::test_fixture::codec_request_fixture();
        let mut trace = request.decode_trace().unwrap();
        trace.finalization.nonce = GoldilocksField(3);
        let call_data = request.trace_json.decode().unwrap().call_data;
        request.trace_json = JsonText::from_value(&psy_prover::trace::GeneratedTxTraceJson::from_trace(&trace, call_data).unwrap()).unwrap();
        request.session_nonce = 3;
        let record = GuardianSessionRecord {
            request_json: JsonText::from_value(&request).unwrap(),
            signatures_json: JsonText::from_value(&signatures()).unwrap(),
            endcap_input_json: JsonText::from_value(&request.decode_trace().unwrap().finalization.submit_end_cap_input).unwrap(),
            endcap_proof_hex: "0xaa".to_owned(), included_checkpoint_id: 1, included_checkpoint_hash: QHashOut::from_values(1, 2, 3, 4),
        };
        let page = serde_json::to_vec(&GuardianSessionsResponse { sessions: vec![record], next_after_nonce: 3, has_more: false }).unwrap();
        let pruned = protocol::encode_record(&page).unwrap();
        let empty = protocol::encode_record(&serde_json::to_vec(&GuardianSessionsResponse { sessions: Vec::new(), next_after_nonce: 0, has_more: false }).unwrap()).unwrap();
        let origins = [serve_typed(200, GUARDIAN_RECORD, pruned, Duration::ZERO), serve_typed(200, GUARDIAN_RECORD, empty, Duration::ZERO), refused_origin()];
        let selected = drive(async { GuardianClient::new(&origins).unwrap().session_record(0).await.unwrap() });
        assert!(selected.is_none());
    }

    /// A reset journal keeps the account at nonce N and no request rows. The next request is N+1
    /// and must be accepted even though row N, which the predecessor check would want, is gone.
    #[test]
    fn save_request_skips_the_predecessor_row_when_it_is_the_reset_cursor() {
        let (path, db) = fresh();
        let request = import_request(4, QHashOut::from_values(5, 6, 7, 8), QHashOut::from_values(9, 9, 9, 9));
        let frozen = JsonText::from_value(&request).unwrap();
        let account = GuardianAccount {
            network_magic: request.network_magic, user_id: request.user_id,
            state: guardian_common::protocol::GuardianAccountState::Active,
            last_checkpoint_id: 7, last_checkpoint_hash: QHashOut::from_values(1, 2, 3, 4),
            imported_nonce: Some(3), imported_ending_leaf: Some(QHashOut::from_values(5, 6, 7, 8)),
            account_public_key: fixture_config().account_public_key().unwrap(),
            withdrawal_chains: Vec::new(), halt_reason: None,
        };
        write_raw_account(&db, &account);
        assert!(retained_keys(&db).is_empty());
        db.save_request(&fixture_config(), &frozen, &[], &[]).unwrap();
        assert_eq!(retained_keys(&db), vec![4]);
        assert_eq!(db.pending_request().unwrap().unwrap().as_str(), frozen.as_str());
        // The skip is exactly one nonce wide: N+2 is still refused, and so is a repeat of N.
        let beyond = import_request(5, QHashOut::from_values(5, 6, 7, 8), QHashOut::from_values(9, 9, 9, 9));
        assert!(db.save_request(&fixture_config(), &JsonText::from_value(&beyond).unwrap(), &[], &[]).is_err());
        let repeated = import_request(3, protocol::Hash4::ZERO, QHashOut::from_values(5, 6, 7, 8));
        assert!(db.save_request(&fixture_config(), &JsonText::from_value(&repeated).unwrap(), &[], &[]).is_err());
        assert_eq!(retained_keys(&db), vec![4]);
        std::fs::remove_dir_all(path).unwrap();
    }

    /// Migration must accept the two reset shapes: the cursor alone, and the cursor plus exactly
    /// one unresolved successor. Included history is unchanged and still fails closed.
    #[test]
    fn retained_suffix_accepts_a_reset_cursor_with_nothing_or_one_pending_successor() {
        let (path, db) = fresh();
        let request = import_request(4, QHashOut::from_values(5, 6, 7, 8), QHashOut::from_values(9, 9, 9, 9));
        let account = GuardianAccount {
            network_magic: request.network_magic, user_id: request.user_id,
            state: guardian_common::protocol::GuardianAccountState::Active,
            last_checkpoint_id: 7, last_checkpoint_hash: QHashOut::from_values(1, 2, 3, 4),
            imported_nonce: Some(3), imported_ending_leaf: Some(QHashOut::from_values(5, 6, 7, 8)),
            account_public_key: fixture_config().account_public_key().unwrap(),
            withdrawal_chains: Vec::new(), halt_reason: None,
        };
        write_raw_account(&db, &account);
        assert_eq!(migrate_relayer_journal(&db.db, &fixture_config()).unwrap(), 0);
        db.save_request(&fixture_config(), &JsonText::from_value(&request).unwrap(), &[], &[]).unwrap();
        assert_eq!(migrate_relayer_journal(&db.db, &fixture_config()).unwrap(), 1);
        // Two unresolved rows, or a pending row that is not the successor, are still refused.
        let fifth = import_request(5, QHashOut::from_values(5, 6, 7, 8), QHashOut::from_values(9, 9, 9, 9));
        write_raw_request(&db, 5, &Request::Request { request: JsonText::from_value(&fifth).unwrap().as_str().to_owned(), deposit_tree_states: Vec::new() });
        assert!(migrate_relayer_journal(&db.db, &fixture_config()).is_err());
        remove_raw_request(&db, 4);
        assert!(migrate_relayer_journal(&db.db, &fixture_config()).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
}

