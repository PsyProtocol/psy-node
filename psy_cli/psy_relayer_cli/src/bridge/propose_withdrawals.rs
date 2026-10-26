use std::time::{Duration, Instant};

use clap::Args;
use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::poseidon::PoseidonHash,
    plonk::config::Hasher,
};
use psy_client_common::args::ContractCallArgs;
use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
use psy_provider::provider::RpcProvider;
use serde::{Deserialize, Serialize};

use crate::bridge::api_client::{ApiResponse, build_default_http_client, get_services_json};
use crate::bridge::constants::{BRIDGE_USER_ID_U64, WITHDRAWAL_TREE_CONTRACT_ID};

// ── CLI args ─────────────────────────────────────────────────────────────────

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct ProposeWithdrawalsArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[clap(long, env = "PSY_GUARDIAN_ROOT")]
    pub guardian_root: String,
    #[clap(long, env = "PSY_SERVICES_URL")]
    pub services_url: Option<String>,
    #[clap(long, env = "PSY_WITHDRAW_METHOD_ID")]
    pub withdraw_method_id: u64,

    #[clap(long, env = "PSY_WITHDRAWAL_STATE_FILE")]
    pub state_file: Option<String>,

    #[clap(long, default_value_t = true, action = clap::ArgAction::Set, env = "PSY_NOTIFY_COORDINATOR")]
    pub notify_coordinator: bool,
    #[clap(long, default_value_t = 120, env = "PSY_POLL_TIMEOUT_SECS")]
    pub poll_timeout_secs: u64,
    /// Polling interval in seconds when waiting for checkpoint advancement.
    #[clap(long, default_value_t = 5, env = "PSY_POLL_INTERVAL_SECS")]
    pub poll_interval_secs: u64,

    /// Destination L1 chain indices to scan when psy-services indexes multiple
    /// L1 chains (comma-separated). Empty keeps the legacy unfiltered query,
    /// which only single-chain services deployments accept.
    #[clap(long, env = "PSY_DESTINATION_CHAIN_INDICES", value_delimiter = ',')]
    pub destination_chain_indices: Vec<u64>,
    /// Local deployment documents. Repeated flags replace the network `l1_config_url`.
    #[clap(long = "l1-config")]
    pub l1_config: Vec<std::path::PathBuf>,
}

// ── constants ────────────────────────────────────────────────────────────────

const UNKNOWN_WITHDRAWAL_TREE_ROOT: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

// ── internal types ───────────────────────────────────────────────────────────

/// A withdrawal discovered by scanning L2 events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingWithdrawal {
    pub event_id: i64,
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub sender_user_id: u64,
    pub contract_id: u64,
    pub destination_chain_index: u64,
    pub token_address: [u32; 8],
    pub amount: [u32; 8],
    pub recipient: [u32; 8],
    pub nonce: [u32; 8],
    pub leaf_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposeResult {
    pub observed_checkpoint_id: u64,
    pub withdrawal_tree_root: String,
    #[serde(default)]
    pub withdrawals: Vec<PendingWithdrawal>,
}

#[derive(Debug, Clone, Default)]
pub struct WithdrawalRoundPlan {
    pub append_withdrawals: Vec<PendingWithdrawal>,
    pub claim_withdrawals: Vec<PendingWithdrawal>,
}

pub fn build_append_withdrawal_calls(withdrawals: &[PendingWithdrawal]) -> anyhow::Result<Vec<ContractCallArgs>> {
    if withdrawals.is_empty() {
        return Ok(Vec::new());
    }

    let mut calls = Vec::with_capacity(withdrawals.len());
    for w in withdrawals {
        // New append_withdrawal input order:
        //   sender_user_id, token_contract_id, destination_chain_index,
        //   token[8], amount[8], recipient[8], nonce[8]
        let mut inputs = Vec::with_capacity(3 + 8 * 4);
        inputs.push(w.sender_user_id);
        inputs.push(w.contract_id);
        inputs.push(w.destination_chain_index);
        inputs.extend(w.token_address.iter().map(|&v| v as u64));
        inputs.extend(w.amount.iter().map(|&v| v as u64));
        inputs.extend(w.recipient.iter().map(|&v| v as u64));
        inputs.extend(w.nonce.iter().map(|&v| v as u64));
        tracing::info!(
            sender_user_id = w.sender_user_id,
            contract_id = w.contract_id,
            destination_chain_index = w.destination_chain_index,
            nonce = ?w.nonce,
            leaf_hash = %w.leaf_hash,
            "building individual append_withdrawal call"
        );
        calls.push(ContractCallArgs {
            contract_id: WITHDRAWAL_TREE_CONTRACT_ID as u64,
            method_name: "append_withdrawal".to_string(),
            inputs,
        });
    }

    Ok(calls)
}

// ── psy-services API response types ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GetBridgeWithdrawalsResponse {
    pub withdrawals: Vec<BridgeWithdrawalEntry>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
struct LatestCheckpointResponse {
    pub checkpoint_id: u64,
}

#[derive(Debug, Deserialize)]
struct BridgeWithdrawalEntry {
    pub event_id: i64,
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub sender_user_id: u64,
    pub contract_id: u64,
    pub destination_chain_index: u64,
    pub token_address_limbs: Option<[u32; 8]>,
    pub token_address_hex: Option<String>,
    pub amount_limbs: Option<[u32; 8]>,
    pub amount_hex: Option<String>,
    pub recipient_limbs: Option<[u32; 8]>,
    pub recipient_hex: Option<String>,
    pub nonce_limbs: Option<[u32; 8]>,
    pub nonce_hex: Option<String>,
    pub leaf_hash: String,
}

impl BridgeWithdrawalEntry {
    fn token_address_words(&self) -> anyhow::Result<[u32; 8]> {
        if let Some(words) = self.token_address_limbs {
            return Ok(words);
        }
        let hex = self
            .token_address_hex
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("bridge withdrawal entry missing token_address_limbs and token_address_hex"))?;
        parse_u32x8_from_hex(hex)
    }

    fn amount_words(&self) -> anyhow::Result<[u32; 8]> {
        if let Some(words) = self.amount_limbs {
            return Ok(words);
        }
        let hex = self
            .amount_hex
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("bridge withdrawal entry missing amount_limbs and amount_hex"))?;
        parse_u32x8_from_hex(hex)
    }

    fn recipient_words(&self) -> anyhow::Result<[u32; 8]> {
        if let Some(words) = self.recipient_limbs {
            return Ok(words);
        }
        let hex = self
            .recipient_hex
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("bridge withdrawal entry missing recipient_limbs and recipient_hex"))?;
        parse_u32x8_from_hex(hex)
    }

    fn nonce_words(&self) -> anyhow::Result<[u32; 8]> {
        if let Some(words) = self.nonce_limbs {
            return Ok(words);
        }
        let hex = self
            .nonce_hex
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("bridge withdrawal entry missing nonce_limbs and nonce_hex"))?;
        parse_u32x8_from_hex(hex)
    }
}

// ── state-file types ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct WithdrawalProposerState {
    pub last_processed_checkpoint_id: u64,
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Resolve the psy-services base URL from CLI arg, env, or config.
fn resolve_services_url(cli_url: &Option<String>, network: &psy_config::NetworkConfigGoldilocks) -> anyhow::Result<String> {
    if let Some(url) = cli_url {
        return Ok(url.trim_end_matches('/').to_string());
    }
    if let Some(urls) = &network.api_services_url {
        if let Some(first) = urls.first() {
            return Ok(first.trim_end_matches('/').to_string());
        }
    }
    anyhow::bail!("no psy-services URL: pass --services-url or set api_services_url in config")
}

/// Determine the half-open checkpoint range [from_checkpoint, to_checkpoint_exclusive)
/// based on CLI args and state file.
fn resolve_scan_range(args: &ProposeWithdrawalsArgs) -> anyhow::Result<(u64, u64)> {
    let from = if let Some(saved) = load_state_checkpoint(&args.state_file)? {
        saved
    } else {
        0
    };

    let to = from + 10;

    Ok((from, to))
}

/// Read last_processed_checkpoint_id from state file (returns None if absent).
fn load_state_checkpoint(state_file: &Option<String>) -> anyhow::Result<Option<u64>> {
    let path = match state_file {
        Some(p) => p,
        None => return Ok(None),
    };
    if !std::path::Path::new(path).exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("read state file '{}': {}", path, e))?;
    let state: WithdrawalProposerState = serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("parse state file '{}': {}", path, e))?;
    tracing::debug!(last_processed = state.last_processed_checkpoint_id, path, "loaded state file");
    Ok(Some(state.last_processed_checkpoint_id))
}

/// Persist the next checkpoint to scan to the state file (no-op if path is None).
fn save_state_checkpoint(state_file: &Option<String>, next_from_checkpoint: u64) -> anyhow::Result<()> {
    let path = match state_file {
        Some(p) => p,
        None => return Ok(()),
    };
    let state = WithdrawalProposerState {
        last_processed_checkpoint_id: next_from_checkpoint,
    };
    std::fs::write(path, serde_json::to_string_pretty(&state)?).map_err(|e| anyhow::anyhow!("write state file '{}': {}", path, e))?;
    tracing::debug!(next_from_checkpoint, path, "saved state file");
    Ok(())
}

async fn fetch_bridge_withdrawals(
    http: &reqwest::Client,
    base_url: &str,
    initial_event_offset: u64,
    destination_chain_index: Option<u64>,
) -> anyhow::Result<Vec<BridgeWithdrawalEntry>> {
    let mut all_withdrawals: Vec<BridgeWithdrawalEntry> = Vec::new();
    let limit: u32 = 1_000;
    let mut offset: u64 = initial_event_offset;

    loop {
        let chain_param = destination_chain_index
            .map(|index| format!("&destination_chain_index={index}"))
            .unwrap_or_default();
        let url = format!(
            "{}/api/v1/bridge/withdrawals?limit={}&offset={}{}",
            base_url, limit, offset, chain_param,
        );
        tracing::debug!(url = %url, "fetching bridge withdrawals page");

        let response = http.get(&url).send().await?.error_for_status()?;
        let status = response.status();
        let body = response.text().await?;
        let resp: ApiResponse<GetBridgeWithdrawalsResponse> = match serde_json::from_str(&body) {
            Ok(parsed) => parsed,
            Err(err) => {
                tracing::error!(
                    url = %url,
                    status = %status,
                    body_len = body.len(),
                    body = %body,
                    error = %err,
                    "[BRIDGE_WITHDRAWALS_DECODE_FAIL] failed to decode fallback withdrawals response"
                );
                return Err(anyhow::anyhow!("Failed to parse bridge withdrawals response: {}", err));
            }
        };

        if !resp.success {
            tracing::error!(
                url = %url,
                status = %status,
                body_len = body.len(),
                body = %body,
                api_error = %resp.error.clone().unwrap_or_else(|| "unknown".into()),
                "[BRIDGE_WITHDRAWALS_API_ERROR] fallback withdrawals API returned error"
            );
            anyhow::bail!("psy-services error: {}", resp.error.unwrap_or_else(|| "unknown".into()));
        }

        let data = resp.data.ok_or_else(|| anyhow::anyhow!("psy-services returned success but no data"))?;
        let total = u64::try_from(data.total)
            .map_err(|_| anyhow::anyhow!("psy-services returned negative withdrawal total {}", data.total))?;
        let page_len = u64::try_from(data.withdrawals.len())?;
        let next_offset = offset.checked_add(page_len)
            .ok_or_else(|| anyhow::anyhow!("withdrawal offset overflow at {} with {} returned rows", offset, page_len))?;
        anyhow::ensure!(
            page_len != 0 || offset >= total,
            "psy-services returned an empty withdrawal page at offset {} before total {}",
            offset, total,
        );
        all_withdrawals.extend(data.withdrawals);
        if next_offset >= total {
            break;
        }
        offset = next_offset;
    }

    Ok(all_withdrawals)
}

async fn fetch_services_latest_checkpoint(http: &reqwest::Client, base_url: &str) -> anyhow::Result<u64> {
    let url = format!("{}/api/v1/checkpoint/latest", base_url);
    let resp: ApiResponse<LatestCheckpointResponse> = get_services_json(http, &url, "latest_checkpoint").await?;

    if !resp.success {
        anyhow::bail!(
            "psy-services latest checkpoint error: {}",
            resp.error.unwrap_or_else(|| "unknown".into())
        );
    }

    Ok(resp
        .data
        .ok_or_else(|| anyhow::anyhow!("psy-services returned success but no latest checkpoint data"))?
        .checkpoint_id)
}

/// Poll the realm's latest_block_state until checkpoint_id advances beyond
/// `before_checkpoint_id`, then return the new checkpoint_id.
pub async fn poll_realm_checkpoint_advance(
    provider: &RpcProvider,
    before_checkpoint_id: u64,
    timeout_secs: u64,
    poll_interval_secs: u64,
) -> anyhow::Result<u64> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    tracing::info!(before_checkpoint_id, timeout_secs, "waiting for realm checkpoint to advance");
    loop {
        let state = provider.get_realm_latest_block_state().await?;
        if state.checkpoint_id > before_checkpoint_id {
            tracing::info!(new_checkpoint_id = state.checkpoint_id, "realm checkpoint advanced");
            return Ok(state.checkpoint_id);
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "timeout ({timeout_secs}s) waiting for realm checkpoint to advance \
                 beyond {before_checkpoint_id}"
            );
        }
        tracing::debug!(
            current = state.checkpoint_id,
            waiting_for_gt = before_checkpoint_id,
            "realm checkpoint not yet advanced, sleeping"
        );
        tokio::time::sleep(Duration::from_secs(poll_interval_secs)).await;
    }
}

fn parse_u32x8_from_hex(hex_str: &str) -> anyhow::Result<[u32; 8]> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)?;
    anyhow::ensure!(bytes.len() == 32, "expected 32-byte hex, got {} bytes", bytes.len());
    let mut out = [0u32; 8];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        out[i] = u32::from_be_bytes(chunk.try_into().expect("4-byte chunk"));
    }
    Ok(out)
}

pub(crate) fn compute_withdrawal_leaf_words(
    sender_user_id: u64,
    recipient: [u32; 8],
    token_address: [u32; 8],
    amount: [u32; 8],
    nonce: [u32; 8],
    destination_chain_index: u64,
) -> anyhow::Result<[u32; 8]> {
    let sender_user_id_u32 = u32::try_from(sender_user_id)
        .map_err(|_| anyhow::anyhow!("sender_user_id {} exceeds uint32 bridge encoding", sender_user_id))?;
    let destination_chain_u32 = u32::try_from(destination_chain_index).map_err(|_| {
        anyhow::anyhow!(
            "destination_chain_index {} exceeds uint32 bridge encoding",
            destination_chain_index
        )
    })?;

    // Leaf hash preimage (34 felts), matching the withdrawal-batch-claim circuit:
    //   sender_user_id, recipient[8], token_address[8], amount[8],
    //   nonce[8], destination_chain_index
    let felts = std::iter::once(GoldilocksField::from_canonical_u32(sender_user_id_u32))
        .chain(recipient.into_iter().map(GoldilocksField::from_canonical_u32))
        .chain(token_address.into_iter().map(GoldilocksField::from_canonical_u32))
        .chain(amount.into_iter().map(GoldilocksField::from_canonical_u32))
        .chain(nonce.into_iter().map(GoldilocksField::from_canonical_u32))
        .chain(std::iter::once(GoldilocksField::from_canonical_u32(destination_chain_u32)))
        .collect::<Vec<_>>();
    let leaf_hash = QHashOut(PoseidonHash::hash_no_pad(&felts));
    let elems = leaf_hash.0.elements;
    Ok([
        (elems[0].to_canonical_u64() & 0xffff_ffff) as u32,
        (elems[0].to_canonical_u64() >> 32) as u32,
        (elems[1].to_canonical_u64() & 0xffff_ffff) as u32,
        (elems[1].to_canonical_u64() >> 32) as u32,
        (elems[2].to_canonical_u64() & 0xffff_ffff) as u32,
        (elems[2].to_canonical_u64() >> 32) as u32,
        (elems[3].to_canonical_u64() & 0xffff_ffff) as u32,
        (elems[3].to_canonical_u64() >> 32) as u32,
    ])
}

pub(crate) fn compute_withdrawal_leaf_hash(
    sender_user_id: u64,
    recipient: [u32; 8],
    token_address: [u32; 8],
    amount: [u32; 8],
    nonce: [u32; 8],
    destination_chain_index: u64,
) -> anyhow::Result<String> {
    let words = compute_withdrawal_leaf_words(
        sender_user_id,
        recipient,
        token_address,
        amount,
        nonce,
        destination_chain_index,
    )?;
    let mut bytes = [0u8; 32];
    for (i, &w) in words.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
    }
    Ok(format!("0x{}", hex::encode(bytes)))
}

/// `chain_offsets` carries one `(destination_chain_index, event_offset)` pair
/// per L1 chain. Each chain's filtered event stream starts at that offset and
/// keeps paging until the filtered total is collected. An empty slice falls
/// back to `args.destination_chain_indices` with offset 0, and when that is
/// empty too, to the legacy unfiltered single-chain query.
pub async fn fetch_pending_bridge_withdrawals(
    args: &ProposeWithdrawalsArgs,
    _from_checkpoint: u64,
    _to_checkpoint_exclusive: u64,
    chain_offsets: &[(u64, u64)],
    network: &psy_config::NetworkConfigGoldilocks,
) -> anyhow::Result<Vec<PendingWithdrawal>> {

    let http = build_default_http_client()?;
    let services_url = resolve_services_url(&args.services_url, network)?;

    let requested: Vec<(u64, u64)> = if chain_offsets.is_empty() {
        args.destination_chain_indices
            .iter()
            .map(|&index| (index, 0))
            .collect()
    } else {
        chain_offsets.to_vec()
    };

    let mut service_withdrawals: Vec<BridgeWithdrawalEntry> = Vec::new();
    if requested.is_empty() {
        service_withdrawals = fetch_bridge_withdrawals(&http, &services_url, 0, None).await?;
    } else {
        for &(chain_index, offset) in &requested {
            let mut page =
                fetch_bridge_withdrawals(&http, &services_url, offset, Some(chain_index)).await?;
            tracing::info!(
                chain_index,
                withdrawals = page.len(),
                offset,
                "fetched bridge withdrawals for destination chain (single pass, no retry)"
            );
            service_withdrawals.append(&mut page);
        }
    }
    // Services returns one row per indexed leaf. Keep each chain's event_id
    // order; do not reorder by sender, contract, or nonce.
    service_withdrawals.sort_by(|left, right| {
        left.destination_chain_index
            .cmp(&right.destination_chain_index)
            .then(left.event_id.cmp(&right.event_id))
    });

    let mut withdrawals: Vec<PendingWithdrawal> = Vec::new();

    for withdrawal in service_withdrawals {
        // Each chain's event offset is the first unappended indexed leaf.
        // Rows stay 1:1 with leaves; a hash or proof-field failure rejects
        // the whole chain prefix instead of skipping a row.
        tracing::debug!(
            event_id = withdrawal.event_id,
            checkpoint_id = withdrawal.checkpoint_id,
            nonce = ?withdrawal.nonce_limbs,
            destination_chain_index = withdrawal.destination_chain_index,
            leaf_hash = %withdrawal.leaf_hash,
            "evaluated indexed bridge withdrawal"
        );

        let token_words = withdrawal.token_address_words().map_err(|error| {
            anyhow::anyhow!(
                "indexed withdrawal prefix malformed at chain {} event_id {}: {error}",
                withdrawal.destination_chain_index,
                withdrawal.event_id
            )
        })?;
        let amount_words = withdrawal.amount_words().map_err(|error| {
            anyhow::anyhow!(
                "indexed withdrawal prefix malformed at chain {} event_id {}: {error}",
                withdrawal.destination_chain_index,
                withdrawal.event_id
            )
        })?;
        let recipient_words = withdrawal.recipient_words().map_err(|error| {
            anyhow::anyhow!(
                "indexed withdrawal prefix malformed at chain {} event_id {}: {error}",
                withdrawal.destination_chain_index,
                withdrawal.event_id
            )
        })?;
        let nonce_words = withdrawal.nonce_words().map_err(|error| {
            anyhow::anyhow!(
                "indexed withdrawal prefix malformed at chain {} event_id {}: {error}",
                withdrawal.destination_chain_index,
                withdrawal.event_id
            )
        })?;
        let local_leaf = compute_withdrawal_leaf_hash(
            withdrawal.sender_user_id,
            recipient_words,
            token_words,
            amount_words,
            nonce_words,
            withdrawal.destination_chain_index,
        )?;
        if local_leaf != withdrawal.leaf_hash {
            anyhow::bail!(
                "indexed withdrawal prefix leaf hash mismatch at chain {} event_id {}: local {local_leaf} services {}",
                withdrawal.destination_chain_index,
                withdrawal.event_id,
                withdrawal.leaf_hash
            );
        }

        withdrawals.push(PendingWithdrawal {
            event_id: withdrawal.event_id,
            checkpoint_id: withdrawal.checkpoint_id,
            user_id: withdrawal.user_id,
            sender_user_id: withdrawal.sender_user_id,
            contract_id: withdrawal.contract_id,
            destination_chain_index: withdrawal.destination_chain_index,
            token_address: token_words,
            amount: amount_words,
            recipient: recipient_words,
            nonce: nonce_words,
            leaf_hash: withdrawal.leaf_hash,
        });
    }

    let withdrawals = select_indexed_withdrawals(withdrawals)?;

    Ok(withdrawals)
}

/// Keep one output row per indexed services row.
///
/// Order is `(destination_chain_index, event_id ASC)`, the stable order of
/// each chain's offset query. `event_id` is the global `contract_events.id`,
/// so values on one chain are not numerically consecutive. Equal nonces,
/// senders, and contracts stay distinct leaves; L1 decides claim eligibility.
/// No row is dropped and no placeholder leaf is inserted.
fn select_indexed_withdrawals(mut withdrawals: Vec<PendingWithdrawal>) -> anyhow::Result<Vec<PendingWithdrawal>> {
    withdrawals.sort_by(|left, right| {
        left.destination_chain_index
            .cmp(&right.destination_chain_index)
            .then(left.event_id.cmp(&right.event_id))
    });
    Ok(withdrawals)
}

pub async fn build_withdrawal_round_plan(
    args: &ProposeWithdrawalsArgs,
    from_checkpoint: u64,
    to_checkpoint_exclusive: u64,
    network: &psy_config::NetworkConfigGoldilocks,
) -> anyhow::Result<WithdrawalRoundPlan> {
    let discovered = fetch_pending_bridge_withdrawals(args, from_checkpoint, to_checkpoint_exclusive, &[], network).await?;
    let mut plan = WithdrawalRoundPlan::default();
    for withdrawal in discovered {
        plan.append_withdrawals.push(withdrawal.clone());
        plan.claim_withdrawals.push(withdrawal);
    }
    Ok(plan)
}

pub async fn discover_withdrawals(
    args: &ProposeWithdrawalsArgs,
    from_checkpoint: u64,
    to_checkpoint_exclusive: u64,
    network: &psy_config::NetworkConfigGoldilocks,
) -> anyhow::Result<Vec<PendingWithdrawal>> {
    Ok(build_withdrawal_round_plan(args, from_checkpoint, to_checkpoint_exclusive, network)
        .await?
        .append_withdrawals)
}

pub async fn poll_withdrawal_tree_root_after_submission(
    _args: &ProposeWithdrawalsArgs,
    provider: &RpcProvider,
    realm_checkpoint_before: u64,
    poll_timeout_secs: u64,
    poll_interval_secs: u64,
) -> anyhow::Result<(u64, String)> {
    let new_realm_checkpoint =
        poll_realm_checkpoint_advance(provider, realm_checkpoint_before, poll_timeout_secs, poll_interval_secs).await?;
    let withdrawal_tree_root = provider
        .get_proposed_withdrawal_tree_root(new_realm_checkpoint, BRIDGE_USER_ID_U64)
        .await?;
    Ok((new_realm_checkpoint, withdrawal_tree_root))
}

// ── main entry point ─────────────────────────────────────────────────────────

pub async fn run_and_get_withdrawal_root(
    args: ProposeWithdrawalsArgs,
    from_checkpoint: u64,
    to_checkpoint_exclusive: u64,
    guardian: &super::guardian_client::LoadedGuardianConfig,
    guardian_provider: &psy_provider::provider::RpcProvider,
) -> anyhow::Result<ProposeResult> {

    let provider = guardian_provider;
    let http = build_default_http_client()?;

    let latest_checkpoint = provider.get_coordinator_latest_block_state().await?.checkpoint_id;

    if from_checkpoint >= to_checkpoint_exclusive {
        tracing::info!(from_checkpoint, to_checkpoint_exclusive, "scan range is empty — nothing to do");
        let lookup_checkpoint = from_checkpoint.saturating_sub(1);
        return Ok(ProposeResult {
            observed_checkpoint_id: lookup_checkpoint,
            withdrawal_tree_root: UNKNOWN_WITHDRAWAL_TREE_ROOT.to_string(),
            withdrawals: Vec::new(),
        });
    }

    let to_checkpoint_inclusive = to_checkpoint_exclusive - 1;

    if latest_checkpoint < to_checkpoint_inclusive {
        anyhow::bail!(
            "scan range overlaps latest checkpoint: latest_checkpoint={} to_checkpoint_exclusive={}",
            latest_checkpoint,
            to_checkpoint_exclusive
        );
    }

    tracing::info!(
        from_checkpoint,
        to_checkpoint_exclusive,
        to_checkpoint_inclusive,
        "scanning checkpoint range for withdrawal events"
    );

    // Ensure psy-services/indexer has caught up past our scan range before
    // querying, so we know the result is definitive.
    let services_url = resolve_services_url(&args.services_url, &guardian.root.network)?;
    let services_latest_checkpoint = fetch_services_latest_checkpoint(&http, &services_url).await?;
    if services_latest_checkpoint <= to_checkpoint_inclusive {
        anyhow::bail!(
            "services not caught up: services_latest_checkpoint={} <= to_checkpoint_inclusive={}",
            services_latest_checkpoint, to_checkpoint_inclusive
        );
    }

    let discovered = fetch_pending_bridge_withdrawals(&args, from_checkpoint, to_checkpoint_exclusive, &[], &guardian.root.network).await?;

    if discovered.is_empty() {
        tracing::info!(from_checkpoint, to_checkpoint_exclusive, "no withdrawal events found in range");
        return Ok(ProposeResult {
            observed_checkpoint_id: to_checkpoint_inclusive,
            withdrawal_tree_root: UNKNOWN_WITHDRAWAL_TREE_ROOT.to_string(),
            withdrawals: Vec::new(),
        });
    }

    tracing::info!(
        count = discovered.len(),
        from_checkpoint,
        to_checkpoint_exclusive,
        "discovered pending bridge withdrawals, building append_withdrawal calls"
    );

    // Append and batch calls stay the mainnet withdrawal-tree scheme.
    // Standalone signing uses the existing guardian submission flow.
    let calls = super::daemon::build_withdrawal_batch_calls(&discovered);
    let checkpoint = super::daemon::submit_guardian_calls(
        guardian,
        guardian_provider,
        calls,
        &discovered,
    )
    .await?;
    let withdrawal_tree_root = provider
        .get_proposed_withdrawal_tree_root(checkpoint, BRIDGE_USER_ID_U64)
        .await?;
    Ok(ProposeResult {
        observed_checkpoint_id: checkpoint,
        withdrawal_tree_root,
        withdrawals: discovered,
    })
}

pub async fn run(args: ProposeWithdrawalsArgs) -> anyhow::Result<()> {
    let history = super::guardian_client::LoadedGuardianConfig::load(std::path::Path::new(&args.rpc_config), std::path::Path::new(&args.guardian_root), &args.l1_config).await?;
    let provider = guardian_common::runtime::load_network(&history.root).map_err(|error| anyhow::anyhow!("{error}"))?;
    let (from_checkpoint, requested_to_checkpoint_exclusive) = resolve_scan_range(&args)?;
    let latest_checkpoint = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
    let active = history.root.l1_chains.iter().map(|chain| u64::from(chain.chain_index)).collect::<std::collections::BTreeSet<_>>();
    let requested = args.destination_chain_indices.iter().copied().collect::<std::collections::BTreeSet<_>>();
    anyhow::ensure!(requested == active, "destination chain indices must equal the active configured chains");
    let to_checkpoint_exclusive = requested_to_checkpoint_exclusive.min(latest_checkpoint);

    tracing::info!(
        from_checkpoint,
        requested_to_checkpoint_exclusive,
        to_checkpoint_exclusive,
        latest_checkpoint,
        "resolved withdrawal scan range"
    );


    tokio::select! {
        result = history.serve_history() => { result?; anyhow::bail!("guardian history listener stopped"); },
        result = run_and_get_withdrawal_root(args.clone(), from_checkpoint, to_checkpoint_exclusive, &history, &provider) => { result?; },
    }
    save_state_checkpoint(&args.state_file, to_checkpoint_exclusive)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn withdrawal_page(event_ids: &[i64], total: i64) -> serde_json::Value {
        let withdrawals: Vec<_> = event_ids.iter().map(|event_id| serde_json::json!({
            "event_id": event_id,
            "checkpoint_id": 10,
            "user_id": 1,
            "sender_user_id": 1,
            "contract_id": 2,
            "destination_chain_index": 2,
            "token_address_limbs": [0, 0, 0, 0, 0, 0, 0, 0],
            "amount_limbs": [1, 0, 0, 0, 0, 0, 0, 0],
            "recipient_limbs": [1, 0, 0, 0, 0, 0, 0, 0],
            "nonce_limbs": [0, 0, 0, 0, 0, 0, 0, 0],
            "leaf_hash": UNKNOWN_WITHDRAWAL_TREE_ROOT,
        })).collect();
        serde_json::json!({"success": true, "data": {"withdrawals": withdrawals, "total": total}})
    }

    async fn fetch_withdrawal_pages(
        initial_offset: u64,
        destination_chain_index: Option<u64>,
        pages: Vec<(u64, serde_json::Value)>,
    ) -> anyhow::Result<anyhow::Result<Vec<BridgeWithdrawalEntry>>> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let http = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(2)).build()?;
        let server = async move {
            for (offset, body) in pages {
                let (socket, _) = listener.accept().await?;
                let mut socket = BufReader::new(socket);
                let mut line = String::new();
                socket.read_line(&mut line).await?;
                let request = reqwest::Url::parse(&format!("http://localhost{}", line.split_whitespace().nth(1)
                    .ok_or_else(|| anyhow::anyhow!("missing request target"))?))?;
                assert_eq!(request.path(), "/api/v1/bridge/withdrawals");
                let mut expected = vec![("limit".to_string(), "1000".to_string()), ("offset".to_string(), offset.to_string())];
                if let Some(chain_index) = destination_chain_index {
                    expected.push(("destination_chain_index".to_string(), chain_index.to_string()));
                }
                assert_eq!(request.query_pairs().into_owned().collect::<Vec<_>>(), expected);
                loop {
                    line.clear();
                    anyhow::ensure!(socket.read_line(&mut line).await? > 0, "incomplete request headers");
                    if line == "\r\n" { break; }
                }
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                socket.get_mut().write_all(response.as_bytes()).await?;
            }
            // Closing the listener makes any request beyond the reported total fail.
            drop(listener);
            Ok::<_, anyhow::Error>(())
        };
        let (result, served) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(5), fetch_bridge_withdrawals(&http, &url, initial_offset, destination_chain_index)),
            tokio::time::timeout(Duration::from_secs(5), server),
        );
        served??;
        Ok(result?)
    }

    #[tokio::test]
    async fn withdrawal_pagination_nonzero_cursor_stops_at_total() -> anyhow::Result<()> {
        let withdrawals = fetch_withdrawal_pages(42, Some(2), vec![(42, withdrawal_page(&[90, 95], 44))]).await??;
        assert_eq!(withdrawals.iter().map(|row| row.event_id).collect::<Vec<_>>(), vec![90, 95]);
        assert!(withdrawals.iter().all(|row| row.destination_chain_index == 2));
        Ok(())
    }

    #[tokio::test]
    async fn withdrawal_pagination_short_pages_advance_by_returned_rows() -> anyhow::Result<()> {
        let withdrawals = fetch_withdrawal_pages(42, Some(2), vec![
            (42, withdrawal_page(&[90, 95], 47)),
            (44, withdrawal_page(&[99], 47)),
            (45, withdrawal_page(&[101, 108], 47)),
        ]).await??;
        assert_eq!(withdrawals.iter().map(|row| row.event_id).collect::<Vec<_>>(), vec![90, 95, 99, 101, 108]);
        Ok(())
    }

    #[tokio::test]
    async fn withdrawal_pagination_empty_page_before_total_fails() -> anyhow::Result<()> {
        let error = fetch_withdrawal_pages(42, Some(2), vec![
            (42, withdrawal_page(&[90, 95], 45)),
            (44, withdrawal_page(&[], 45)),
        ]).await?.expect_err("an incomplete indexed prefix must not be returned");
        assert_eq!(error.to_string(), "psy-services returned an empty withdrawal page at offset 44 before total 45");
        Ok(())
    }

    #[tokio::test]
    async fn withdrawal_pagination_empty_page_at_total_succeeds() -> anyhow::Result<()> {
        for offset in [0, 42] {
            let withdrawals = fetch_withdrawal_pages(offset, None, vec![(offset, withdrawal_page(&[], offset as i64))]).await??;
            assert!(withdrawals.is_empty());
        }
        Ok(())
    }

    #[tokio::test]
    async fn withdrawal_pagination_negative_total_fails() -> anyhow::Result<()> {
        let error = fetch_withdrawal_pages(0, Some(2), vec![(0, withdrawal_page(&[], -1))])
            .await?.expect_err("a negative total must not be accepted");
        assert_eq!(error.to_string(), "psy-services returned negative withdrawal total -1");
        Ok(())
    }

    #[tokio::test]
    async fn withdrawal_pagination_offset_overflow_fails() -> anyhow::Result<()> {
        let error = fetch_withdrawal_pages(u64::MAX, Some(2), vec![(u64::MAX, withdrawal_page(&[90], i64::MAX))])
            .await?.expect_err("an overflowing offset must not wrap or saturate");
        assert_eq!(error.to_string(), format!("withdrawal offset overflow at {} with 1 returned rows", u64::MAX));
        Ok(())
    }

    fn u32x8_be_to_hex(words: [u32; 8]) -> String {
        let mut bytes = [0u8; 32];
        for (i, &word) in words.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        format!("0x{}", hex::encode(bytes))
    }

    #[test]
    fn withdrawal_leaf_hash_binds_sender_user_id() -> anyhow::Result<()> {
        let recipient_hex = "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266";
        let token_hex = "0x00000000000000000000000068b1d87f95878fe05b998f19b66f4baba5de1aed";
        let amount_hex = "0x000000000000000000000000000000000000000000000000000000e8d4a51000";
        let nonce_hex = "0xd6a2e0c60100000000000000000000000000000000000000000000000000000a";
        let destination_chain_index = 0u64;

        let recipient = parse_u32x8_from_hex(recipient_hex)?;
        let token_address = parse_u32x8_from_hex(token_hex)?;
        let amount = parse_u32x8_from_hex(amount_hex)?;
        let nonce = parse_u32x8_from_hex(nonce_hex)?;

        let sender0 = compute_withdrawal_leaf_words(
            0,
            recipient,
            token_address,
            amount,
            nonce,
            destination_chain_index,
        )?;
        let sender1 = compute_withdrawal_leaf_words(
            1,
            recipient,
            token_address,
            amount,
            nonce,
            destination_chain_index,
        )?;
        assert_ne!(sender0, sender1, "sender_user_id must change withdrawal leaf hash");
        assert_eq!(
            compute_withdrawal_leaf_hash(0, recipient, token_address, amount, nonce, destination_chain_index)?,
            u32x8_be_to_hex(sender0),
            "hex helper must match limb helper"
        );

        Ok(())
    }

    fn sample_withdrawal(
        destination_chain_index: u64,
        sender_user_id: u64,
        contract_id: u64,
        nonce: [u32; 8],
        amount: [u32; 8],
        event_id: i64,
    ) -> PendingWithdrawal {
        PendingWithdrawal {
            event_id,
            checkpoint_id: 1,
            user_id: sender_user_id,
            sender_user_id,
            contract_id,
            destination_chain_index,
            token_address: [0; 8],
            amount,
            recipient: [1, 0, 0, 0, 0, 0, 0, 0],
            nonce,
            leaf_hash: String::new(),
        }
    }

    #[test]
    fn select_indexed_withdrawals_preserves_per_chain_event_id_order_and_count() {
        let chain1_late = sample_withdrawal(1, 4, 9, [9, 0, 0, 0, 0, 0, 0, 0], [3, 0, 0, 0, 0, 0, 0, 0], 30);
        let chain1_early = sample_withdrawal(1, 9, 3, [0; 8], [8, 0, 0, 0, 0, 0, 0, 0], 10);
        let chain2_early = sample_withdrawal(2, 1, 1, [0; 8], [1, 0, 0, 0, 0, 0, 0, 0], 4);
        let chain2_late = sample_withdrawal(2, 1, 1, [7, 0, 0, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0, 0, 0], 40);
        let selected = select_indexed_withdrawals(vec![
            chain2_late.clone(),
            chain1_late.clone(),
            chain1_early.clone(),
            chain2_early.clone(),
        ])
        .expect("gapped indexed rows stay in query order");
        let order: Vec<_> = selected.iter().map(|w| (w.destination_chain_index, w.event_id)).collect();
        assert_eq!(order, vec![(1, 10), (1, 30), (2, 4), (2, 40)]);
        assert_eq!(selected.len(), 4);
        assert_eq!(selected[0].sender_user_id, chain1_early.sender_user_id);
        assert_eq!(selected[1].contract_id, chain1_late.contract_id);
    }

    #[test]
    fn select_indexed_withdrawals_keeps_equal_nonces_for_different_users() {
        let nonce = [4, 0, 0, 0, 0, 0, 0, 0];
        let first_user = sample_withdrawal(1, 7, 3, nonce, [9, 0, 0, 0, 0, 0, 0, 0], 20);
        let second_user = sample_withdrawal(1, 8, 3, nonce, [9, 0, 0, 0, 0, 0, 0, 0], 21);
        let selected = select_indexed_withdrawals(vec![second_user.clone(), first_user.clone()]).expect("distinct users");
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].sender_user_id, first_user.sender_user_id);
        assert_eq!(selected[1].sender_user_id, second_user.sender_user_id);
        assert_eq!(selected[0].nonce, selected[1].nonce);
    }

    #[test]
    fn select_indexed_withdrawals_keeps_duplicate_indexed_rows_for_same_burn() {
        let first = sample_withdrawal(1, 7, 3, [4, 0, 0, 0, 0, 0, 0, 0], [9, 0, 0, 0, 0, 0, 0, 0], 11);
        let repeat = sample_withdrawal(1, 7, 3, [4, 0, 0, 0, 0, 0, 0, 0], [9, 0, 0, 0, 0, 0, 0, 0], 12);
        let selected = select_indexed_withdrawals(vec![repeat.clone(), first.clone()]).expect("duplicate indexed rows");
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].event_id, first.event_id);
        assert_eq!(selected[1].event_id, repeat.event_id);
        assert_eq!(selected[0].amount, selected[1].amount);
        assert_eq!(selected[0].nonce, selected[1].nonce);
        assert_eq!(selected[0].sender_user_id, selected[1].sender_user_id);
    }


}
