use alloy_primitives::{Address, U256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{sol, SolCall};
use anyhow::Context;
use std::collections::HashMap;
use std::time::Duration;
use std::{fs, path::PathBuf, str::FromStr};

sol! {
    function l1ChainIndex() external view returns (uint8);
}

pub async fn eth_call_u256<P: Provider, Call: SolCall<Return = U256>>(
    provider: &P,
    to: Address,
    call: Call,
) -> anyhow::Result<U256> {
    let tx = TransactionRequest::default().to(to).input(call.abi_encode().into());
    let raw = provider.call(tx).await.context("eth_call failed")?;
    Call::abi_decode_returns(&raw).context("failed to decode eth_call return")
}

pub async fn eth_call_u32<P: Provider, Call: SolCall<Return = u32>>(
    provider: &P,
    to: Address,
    call: Call,
) -> anyhow::Result<u32> {
    let tx = TransactionRequest::default().to(to).input(call.abi_encode().into());
    let raw = provider.call(tx).await.context("eth_call failed")?;
    Call::abi_decode_returns(&raw).context("failed to decode eth_call return")
}

#[derive(Debug, serde::Deserialize)]
pub struct DeployedContracts {
    #[serde(default)]
    pub protocol: Option<DeployedProtocol>,
    pub core: HashMap<String, String>,
    pub contracts: HashMap<String, String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct DeployedProtocol {
    pub chain: DeployedProtocolChain,
}

#[derive(Debug, serde::Deserialize)]
pub struct DeployedProtocolChain {
    #[serde(rename = "l1ChainIndex")]
    pub l1_chain_index: u8,
}

#[derive(Debug, serde::Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

const AGGREGATION_BODY_LIMIT: usize = 24 * 1024 * 1024;
const AGGREGATION_PROOF_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregationContext {
    pub version: u8,
    pub config_hash: String,
    pub end_checkpoint_id: String,
    pub end_checkpoint_root: [String; 4],
    pub context_id: String,
    pub max_proof_bytes: u32,
    pub max_records: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishAggregationContext {
    #[serde(deserialize_with = "aggregation_required_option")]
    pub expected_context_id: Option<String>,
    pub context: AggregationContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AggregationClaimKind { Withdrawal, Reward }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "version", rename_all = "camelCase", deny_unknown_fields)]
pub enum AggregationClaimRequest {
    #[serde(rename = 1)]
    Withdrawal { #[serde(rename = "contextId")] context_id: String, kind: AggregationClaimKind, record: String, proof: String },
    #[serde(rename = 2)]
    Reward { #[serde(rename = "contextId")] context_id: String, kind: AggregationClaimKind, record: String, transition: String },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregationClaim {
    pub claim_id: String,
    pub request: AggregationClaimRequest,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregationClaimsPage {
    pub claims: Vec<AggregationClaim>,
    #[serde(deserialize_with = "aggregation_required_option")]
    pub next_after_claim_id: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptEvidence {
    pub chain_index: u8,
    pub transaction_hash: String,
    pub log_index: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsumptionEvidence {
    pub chain_index: u8,
    pub block_number: String,
    pub block_hash: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum ClaimDisposition {
    Applied { claim_id: String, receipt: ReceiptEvidence },
    ConsumedElsewhere { claim_id: String, consumption: ConsumptionEvidence },
    Released { claim_id: String },
}

impl ClaimDisposition {
    pub fn claim_id(&self) -> &str {
        match self {
            Self::Applied { claim_id, .. } | Self::ConsumedElsewhere { claim_id, .. }
                | Self::Released { claim_id } => claim_id,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum AggregationDispositions {
    Included { context_id: String, family: u8, opening_digest: String, opening: String, claim_ids: Vec<String> },
    Disposed { family: u8, opening_digest: String, opening: String, dispositions: Vec<ClaimDisposition> },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregationAcknowledgment {
    pub family: u8,
    pub opening_digest: String,
    pub acknowledged_claim_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum AggregationErrorCode {
    InvalidEncoding, ProofTooLarge, InvalidProof, UnsupportedIdentity, ContextChanged,
    ConflictingClaim, AlreadyConsumed, NoCommittedContext, LedgerNotInitialized, Unauthorized, StateMismatch,
    EvidenceUnavailable,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregationErrorData {
    pub error_code: AggregationErrorCode,
    #[serde(deserialize_with = "aggregation_required_option")]
    pub current_context: Option<AggregationContext>,
}

#[derive(Debug)]
pub enum AggregationHttpError {
    Credential,
    InvalidRequest,
    BodyTooLarge,
    InvalidResponse,
    Transport(reqwest::Error),
    Service { status: reqwest::StatusCode, data: AggregationErrorData },
}

impl std::fmt::Display for AggregationHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Credential => f.write_str("aggregation credential unavailable"),
            Self::InvalidRequest => f.write_str("invalid aggregation request"),
            Self::BodyTooLarge => f.write_str("aggregation body exceeds 24 MiB"),
            Self::InvalidResponse => f.write_str("invalid aggregation response"),
            Self::Transport(_) => f.write_str("aggregation transport failed"),
            Self::Service { status, data } => write!(f, "aggregation service {}: {:?}", status, data.error_code),
        }
    }
}

impl std::error::Error for AggregationHttpError {}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AggregationEnvelope<T> {
    success: bool,
    data: T,
    error: Option<String>,
    #[serde(rename = "timestamp")]
    _timestamp: String,
}

fn aggregation_required_option<'de, D: serde::Deserializer<'de>, T: serde::Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    serde::Deserialize::deserialize(deserializer)
}

fn aggregation_hex(value: &str) -> bool {
    value.len() == 66 && value.starts_with("0x")
        && value.as_bytes()[2..].iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

fn aggregation_decimal(value: &str) -> Option<u64> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit()) { return None; }
    value.parse().ok()
}

impl AggregationContext {
    pub fn validate(&self) -> bool {
        self.version == 1 && aggregation_hex(&self.config_hash) && aggregation_hex(&self.context_id)
            && aggregation_decimal(&self.end_checkpoint_id).is_some()
            && self.end_checkpoint_root.iter().all(|v| aggregation_decimal(v)
                .is_some_and(|v| v < psy_client_data::bridge_aggregate::GOLDILOCKS_MODULUS))
            && self.max_proof_bytes == AGGREGATION_PROOF_LIMIT as u32 && self.max_records == 1024
    }
}

pub fn decode_aggregation_base64(value: &str, limit: usize) -> Result<Vec<u8>, AggregationHttpError> {
    use base64::Engine;
    if value.len() > limit.div_ceil(3) * 4 { return Err(AggregationHttpError::BodyTooLarge); }
    let bytes = base64::engine::general_purpose::STANDARD.decode(value)
        .map_err(|_| AggregationHttpError::InvalidRequest)?;
    if bytes.len() > limit { return Err(AggregationHttpError::BodyTooLarge); }
    if base64::engine::general_purpose::STANDARD.encode(&bytes) != value {
        return Err(AggregationHttpError::InvalidRequest);
    }
    Ok(bytes)
}

struct AggregationBody(Vec<u8>);
impl std::io::Write for AggregationBody {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > AGGREGATION_BODY_LIMIT - self.0.len() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "aggregation body limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

fn aggregation_url(services_url: &str, route: &str) -> Result<reqwest::Url, AggregationHttpError> {
    let mut url = reqwest::Url::parse(services_url).map_err(|_| AggregationHttpError::InvalidRequest)?;
    if !matches!(url.scheme(), "http" | "https") || !url.username().is_empty()
        || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return Err(AggregationHttpError::InvalidRequest);
    }
    url.set_path(&format!("/api/v1/bridge/aggregation/{route}"));
    Ok(url)
}

async fn aggregation_http<T: serde::de::DeserializeOwned>(
    request: reqwest::RequestBuilder,
    token_file: &std::path::Path,
    body: Option<&impl serde::Serialize>,
) -> Result<T, AggregationHttpError> {
    let parent = token_file.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
    let name = token_file.file_name().ok_or(AggregationHttpError::Credential)?;
    let token = crate::guardian::runtime::read_protected_file(parent, std::path::Path::new(name), 16384)
        .map_err(|_| AggregationHttpError::Credential)?;
    let token = std::str::from_utf8(&token).map_err(|_| AggregationHttpError::Credential)?;
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(AggregationHttpError::Credential);
    }
    let mut request = request.bearer_auth(token).timeout(Duration::from_secs(30));
    if let Some(body) = body {
        let mut encoded = AggregationBody(Vec::new());
        serde_json::to_writer(&mut encoded, body).map_err(|_| AggregationHttpError::BodyTooLarge)?;
        request = request.header(reqwest::header::CONTENT_TYPE, "application/json").body(encoded.0);
    }
    let mut response = request.send().await.map_err(AggregationHttpError::Transport)?;
    let status = response.status();
    if response.content_length().is_some_and(|n| n > AGGREGATION_BODY_LIMIT as u64) {
        return Err(AggregationHttpError::BodyTooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(AggregationHttpError::Transport)? {
        if chunk.len() > AGGREGATION_BODY_LIMIT - bytes.len() { return Err(AggregationHttpError::BodyTooLarge); }
        bytes.extend_from_slice(&chunk);
    }
    if status.is_success() {
        let envelope: AggregationEnvelope<T> = serde_json::from_slice(&bytes).map_err(|_| AggregationHttpError::InvalidResponse)?;
        if !envelope.success || envelope.error.is_some() { return Err(AggregationHttpError::InvalidResponse); }
        Ok(envelope.data)
    } else {
        let envelope: AggregationEnvelope<AggregationErrorData> = serde_json::from_slice(&bytes)
            .map_err(|_| AggregationHttpError::InvalidResponse)?;
        let expected_status = match envelope.data.error_code {
            AggregationErrorCode::InvalidEncoding => 400,
            AggregationErrorCode::ProofTooLarge => 413,
            AggregationErrorCode::InvalidProof | AggregationErrorCode::UnsupportedIdentity => 422,
            AggregationErrorCode::ContextChanged | AggregationErrorCode::ConflictingClaim
                | AggregationErrorCode::AlreadyConsumed | AggregationErrorCode::StateMismatch => 409,
            AggregationErrorCode::NoCommittedContext | AggregationErrorCode::LedgerNotInitialized | AggregationErrorCode::EvidenceUnavailable => 503,
            AggregationErrorCode::Unauthorized if status.as_u16() == 403 => 403,
            AggregationErrorCode::Unauthorized => 401,
        };
        let context_valid = match (&envelope.data.error_code, &envelope.data.current_context) {
            (AggregationErrorCode::ContextChanged, Some(context)) => context.validate(),
            (AggregationErrorCode::ContextChanged, None) | (_, Some(_)) => false,
            (_, None) => true,
        };
        if envelope.success || envelope.error.is_none() || status.as_u16() != expected_status || !context_valid {
            return Err(AggregationHttpError::InvalidResponse);
        }
        Err(AggregationHttpError::Service { status, data: envelope.data })
    }
}

pub async fn get_aggregation_context(
    http: &reqwest::Client, services_url: &str, token_file: &std::path::Path,
) -> Result<Option<AggregationContext>, AggregationHttpError> {
    let result: Result<AggregationContext, AggregationHttpError> =
        aggregation_http(http.get(aggregation_url(services_url, "context")?), token_file, None::<&()>).await;
    match result {
        Ok(context) if context.validate() => Ok(Some(context)),
        Ok(_) => Err(AggregationHttpError::InvalidResponse),
        Err(AggregationHttpError::Service { status, data })
            if status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                && data.error_code == AggregationErrorCode::NoCommittedContext => Ok(None),
        Err(error) => Err(error),
    }
}

pub async fn publish_aggregation_context(
    http: &reqwest::Client, services_url: &str, token_file: &std::path::Path,
    request: &PublishAggregationContext,
) -> Result<AggregationContext, AggregationHttpError> {
    if !request.context.validate() || request.expected_context_id.as_deref().is_some_and(|id| !aggregation_hex(id)) {
        return Err(AggregationHttpError::InvalidRequest);
    }
    let context: AggregationContext = aggregation_http(http.post(aggregation_url(services_url, "context")?), token_file, Some(request)).await?;
    if context != request.context { return Err(AggregationHttpError::InvalidResponse); }
    Ok(context)
}

pub async fn get_aggregation_claims(
    http: &reqwest::Client, services_url: &str, token_file: &std::path::Path,
    context_id: &str, after_claim_id: Option<&str>, limit: u8,
) -> Result<AggregationClaimsPage, AggregationHttpError> {
    if !aggregation_hex(context_id) || after_claim_id.is_some_and(|id| !aggregation_hex(id)) || !(1..=32).contains(&limit) {
        return Err(AggregationHttpError::InvalidRequest);
    }
    let mut url = aggregation_url(services_url, "claims")?;
    url.query_pairs_mut().append_pair("contextId", context_id).append_pair("limit", &limit.to_string());
    if let Some(after) = after_claim_id { url.query_pairs_mut().append_pair("afterClaimId", after); }
    let page: AggregationClaimsPage = aggregation_http(http.get(url), token_file, None::<&()>).await?;
    if page.claims.len() > limit as usize { return Err(AggregationHttpError::InvalidResponse); }
    let mut previous = after_claim_id;
    for claim in &page.claims {
        if !aggregation_hex(&claim.claim_id) || previous.is_some_and(|id| id >= claim.claim_id.as_str()) { return Err(AggregationHttpError::InvalidResponse); }
        let (claim_context, record, artifact) = match &claim.request {
            AggregationClaimRequest::Withdrawal { context_id, kind, record, proof } => {
                if *kind != AggregationClaimKind::Withdrawal { return Err(AggregationHttpError::InvalidResponse); }
                (context_id, record, proof)
            }
            AggregationClaimRequest::Reward { context_id, kind, record, transition } => {
                if *kind != AggregationClaimKind::Reward { return Err(AggregationHttpError::InvalidResponse); }
                (context_id, record, transition)
            }
        };
        if claim_context != context_id { return Err(AggregationHttpError::InvalidResponse); }
        let record_bytes = decode_aggregation_base64(record, if matches!(claim.request, AggregationClaimRequest::Reward { .. }) { 192 } else { 1024 }).map_err(|_| AggregationHttpError::InvalidResponse)?;
        let valid = match &claim.request {
            AggregationClaimRequest::Withdrawal { .. } => psy_client_data::bridge_aggregate::WithdrawalLeaf::decode(&record_bytes).and_then(|leaf| leaf.validate()).is_ok(),
            AggregationClaimRequest::Reward { .. } => record_bytes.is_empty() || psy_client_data::bridge_aggregate::SourceCheckpointRewardLeaf::decode(&record_bytes).and_then(|leaf| leaf.leaf_commit()).is_ok(),
        };
        if !valid { return Err(AggregationHttpError::InvalidResponse); }
        let artifact = decode_aggregation_base64(artifact, AGGREGATION_PROOF_LIMIT).map_err(|_| AggregationHttpError::InvalidResponse)?;
        if artifact.is_empty() { return Err(AggregationHttpError::InvalidResponse); }
        previous = Some(&claim.claim_id);
    }
    if let Some(cursor) = &page.next_after_claim_id {
        if page.claims.last().map(|claim| &claim.claim_id) != Some(cursor) {
            return Err(AggregationHttpError::InvalidResponse);
        }
    }
    Ok(page)
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RewardLedgerNode {
    pub height: u8,
    pub index: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RewardLedgerSessionState {
    pub context_id: String,
    pub current_root: String,
    pub proof: String,
    pub transition: String,
    pub nodes: Vec<RewardLedgerNode>,
}

pub async fn get_reward_ledger_session_state(
    http: &reqwest::Client, services_url: &str, token_file: &std::path::Path, context_id: &str,
) -> Result<RewardLedgerSessionState, AggregationHttpError> {
    if !aggregation_hex(context_id) { return Err(AggregationHttpError::InvalidRequest); }
    let mut url = aggregation_url(services_url, "session-state")?;
    url.query_pairs_mut().append_pair("contextId", context_id);
    let state: RewardLedgerSessionState = aggregation_http(http.get(url), token_file, None::<&()>).await?;
    if state.context_id != context_id || !aggregation_hex(&state.current_root) || state.nodes.len() != 33 { return Err(AggregationHttpError::InvalidResponse); }
    let proof = decode_aggregation_base64(&state.proof, AGGREGATION_PROOF_LIMIT).map_err(|_| AggregationHttpError::InvalidResponse)?;
    let transition = decode_aggregation_base64(&state.transition, AGGREGATION_PROOF_LIMIT).map_err(|_| AggregationHttpError::InvalidResponse)?;
    if proof.is_empty() || transition.is_empty() || !transition.windows(proof.len()).any(|window| window == proof) { return Err(AggregationHttpError::InvalidResponse); }
    let mut previous_height = None;
    for node in &state.nodes {
        if previous_height.is_some_and(|height| node.height != height + 1) || aggregation_decimal(&node.index).is_none() || !aggregation_hex(&node.hash) { return Err(AggregationHttpError::InvalidResponse); }
        previous_height = Some(node.height);
    }
    if previous_height != Some(32) { return Err(AggregationHttpError::InvalidResponse); }
    Ok(state)
}

pub async fn post_aggregation_dispositions(
    http: &reqwest::Client, services_url: &str, token_file: &std::path::Path,
    request: &AggregationDispositions,
) -> Result<AggregationAcknowledgment, AggregationHttpError> {
    let (family, posted_opening_digest, opening, ids): (u8, &str, &str, Vec<&str>) = match request {
        AggregationDispositions::Included { context_id, family, opening_digest, opening, claim_ids } => {
            if !aggregation_hex(context_id) { return Err(AggregationHttpError::InvalidRequest); }
            (*family, opening_digest.as_str(), opening, claim_ids.iter().map(String::as_str).collect())
        }
        AggregationDispositions::Disposed { family, opening_digest, opening, dispositions } => {
            for disposition in dispositions {
                let valid = match disposition {
                    ClaimDisposition::Applied { receipt, .. } => aggregation_hex(&receipt.transaction_hash) && aggregation_decimal(&receipt.log_index).is_some(),
                    ClaimDisposition::ConsumedElsewhere { consumption, .. } => aggregation_hex(&consumption.block_hash) && aggregation_decimal(&consumption.block_number).is_some(),
                    ClaimDisposition::Released { .. } => true,
                };
                if !valid { return Err(AggregationHttpError::InvalidRequest); }
            }
            (*family, opening_digest.as_str(), opening, dispositions.iter().map(ClaimDisposition::claim_id).collect())
        }
    };
    if !matches!(family, 2 | 3) || !aggregation_hex(posted_opening_digest) || ids.len() > 1024 || ids.iter().any(|id| !aggregation_hex(id))
        || ids.iter().copied().collect::<std::collections::BTreeSet<_>>().len() != ids.len() {
        return Err(AggregationHttpError::InvalidRequest);
    }
    let bytes = decode_aggregation_base64(opening, AGGREGATION_BODY_LIMIT)?;
    match family {
        2 => { psy_client_data::bridge_aggregate::WithdrawalAggregateOpening::decode(&bytes).map_err(|_| AggregationHttpError::InvalidRequest)?; }
        3 => { psy_client_data::bridge_aggregate::SourceCheckpointRewardOpening::decode(&bytes).map_err(|_| AggregationHttpError::InvalidRequest)?; }
        _ => return Err(AggregationHttpError::InvalidRequest),
    }
    let acknowledgment: AggregationAcknowledgment = aggregation_http(http.post(aggregation_url(services_url, "dispositions")?), token_file, Some(request)).await?;
    if acknowledgment.family != family || acknowledgment.opening_digest != posted_opening_digest || !acknowledgment.acknowledged_claim_ids.iter().map(String::as_str).eq(ids) {
        return Err(AggregationHttpError::InvalidResponse);
    }
    Ok(acknowledgment)
}

#[derive(Debug, serde::Deserialize)]
pub struct DepositTreeRootState {
    pub found: bool,
    pub reason: Option<String>,
    pub source_chain_index: Option<u64>,
    pub snapshot_deposit_count: Option<u64>,
    pub target_deposit_count: Option<u64>,
    pub tree_count: Option<u64>,
    pub deposit_root: Option<String>,
}

impl DepositTreeRootState {
    pub fn snapshot_deposit_count(&self) -> Option<u64> {
        self.snapshot_deposit_count
            .or(self.tree_count)
            .or(self.target_deposit_count)
    }
}

pub async fn fetch_services_deposit_tree_root(
    http: &reqwest::Client,
    services_url: &str,
    source_chain_index: u64,
    target_deposit_count: u64,
) -> anyhow::Result<DepositTreeRootState> {
    let mut url = reqwest::Url::parse(&format!(
        "{}/api/v1/bridge/deposit-tree-root",
        services_url.trim_end_matches('/'),
    ))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("source_chain_index", &source_chain_index.to_string());
        let target_deposit_count = target_deposit_count.to_string();
        query.append_pair("target_deposit_count", &target_deposit_count);
    }
    let resp: ApiResponse<DepositTreeRootState> =
        get_services_json(http, url.as_str(), "deposit_tree_root").await?;
    if !resp.success {
        anyhow::bail!(
            "psy-services deposit_tree_root error: {}",
            resp.error.unwrap_or_else(|| "unknown".into())
        );
    }
    resp.data.ok_or_else(|| anyhow::anyhow!("deposit_tree_root response missing data"))
}

pub async fn get_services_json<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    label: &'static str,
) -> anyhow::Result<T> {
    let response = http.get(url).send().await?.error_for_status()?;
    let status = response.status();
    let body = response.text().await?;
    match serde_json::from_str::<T>(&body) {
        Ok(parsed) => Ok(parsed),
        Err(err) => {
            tracing::error!(
                url = %url,
                label,
                status = %status,
                body_len = body.len(),
                body = %body,
                error = %err,
                "[SERVICES_DECODE_FAIL] failed to decode services HTTP response"
            );
            Err(anyhow::anyhow!("Failed to parse {} response: {}", label, err))
        }
    }
}

pub fn build_default_http_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build default HTTP client")
}

pub fn resolve_deployments_file(deployments_network: &str, file_name: &str) -> PathBuf {
    if let Ok(base) = std::env::var("PSY_DEPLOYMENTS_DIR") {
        return PathBuf::from(base).join(deployments_network).join(file_name);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../psy-contracts/deployments")
        .join(deployments_network)
        .join(file_name)
}

pub fn load_deployed_contracts(deployments_network: &str) -> anyhow::Result<DeployedContracts> {
    let path = resolve_deployments_file(deployments_network, "deployed-contracts.json");
    let raw = fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn resolve_contract_address_from_deployments(
    deployments_network: &str,
    contract_name: &str,
) -> anyhow::Result<Address> {
    let path = resolve_deployments_file(deployments_network, "deployed-contracts.json");
    let deployed = load_deployed_contracts(deployments_network)?;
    let addr = deployed
        .core
        .get(contract_name)
        .or_else(|| deployed.contracts.get(contract_name))
        .ok_or_else(|| anyhow::anyhow!("{} not found in {}", contract_name, path.display()))?;
    Address::from_str(addr)
        .with_context(|| format!("invalid {} address in {}: {}", contract_name, path.display(), addr))
}

pub async fn resolve_l1_chain_index<P: Provider>(
    provider: &P,
    deployments_network: &str,
    state_manager: Address,
) -> anyhow::Result<u8> {
    let deployed = load_deployed_contracts(deployments_network)?;
    let expected = deployed
        .protocol
        .as_ref()
        .map(|p| p.chain.l1_chain_index)
        .unwrap_or(0);
    let tx = TransactionRequest::default().to(state_manager).input(l1ChainIndexCall {}.abi_encode().into());
    let raw = provider.call(tx).await.context("StateManager.l1ChainIndex eth_call failed")?;
    let onchain = l1ChainIndexCall::abi_decode_returns(&raw).context("failed to decode StateManager.l1ChainIndex return")?;
    anyhow::ensure!(
        onchain == expected,
        "l1ChainIndex mismatch for {}: deployment={} onchain={} state_manager={}",
        deployments_network,
        expected,
        onchain,
        state_manager
    );
    Ok(onchain)
}
