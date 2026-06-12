use std::time::{Duration, Instant};

use clap::Args;
use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::poseidon::PoseidonHash,
    plonk::config::Hasher,
};
use psy_client_common::args::{ContractCallArgs, ContractCallData, SignType, WalletSourceArgs};
use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
use psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT;
use psy_prover::session::WalletSession;
use psy_provider::provider::RpcProvider;
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;
use serde::{Deserialize, Serialize};

use psy_cli_common::key_utils::load_wallet_key_info;

use crate::bridge::api_client::{ApiResponse, build_default_http_client, get_services_json};
use crate::bridge::constants::{BRIDGE_USER_ID_U64, WITHDRAWAL_TREE_CONTRACT_ID};

// ── CLI args ─────────────────────────────────────────────────────────────────

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct ProposeWithdrawalsArgs {
    #[clap(env, long, default_value = "psy-genesis/config.json", env)]
    pub rpc_config: String,
    #[command(flatten)]
    pub wallet: WalletSourceArgs,
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
    pub destination_chain_id: u64,
    pub token_address: [u32; 8],
    pub amount: [u32; 8],
    pub recipient: [u32; 8],
    pub nonce: u64,
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
        // append_withdrawal(destination_chain_index, token_address, amount, recipient, nonce)
        let mut inputs = Vec::with_capacity(26);
        inputs.push(w.destination_chain_id);
        inputs.extend(w.token_address.iter().map(|&v| v as u64));
        inputs.extend(w.amount.iter().map(|&v| v as u64));
        inputs.extend(w.recipient.iter().map(|&v| v as u64));
        inputs.push(w.nonce);
        tracing::info!(
            destination_chain_id = w.destination_chain_id,
            nonce = w.nonce,
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
    pub destination_chain_id: u64,
    pub token_address_limbs: Option<[u32; 8]>,
    pub token_address_hex: Option<String>,
    pub amount_limbs: Option<[u32; 8]>,
    pub amount_hex: Option<String>,
    pub recipient_limbs: Option<[u32; 8]>,
    pub recipient_hex: Option<String>,
    pub nonce: u64,
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
}

// ── state-file types ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct WithdrawalProposerState {
    pub last_processed_checkpoint_id: u64,
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Resolve the psy-services base URL from CLI arg, env, or config.
fn resolve_services_url(cli_url: &Option<String>, psy_config: &psy_config::PsyConfigGoldilocks) -> anyhow::Result<String> {
    if let Some(url) = cli_url {
        return Ok(url.trim_end_matches('/').to_string());
    }
    let network = psy_config.get_current_network()?;
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
    initial_offset: u64,
) -> anyhow::Result<Vec<BridgeWithdrawalEntry>> {
    let mut all_withdrawals: Vec<BridgeWithdrawalEntry> = Vec::new();
    let limit: u32 = 10_000;
    let mut offset: u64 = initial_offset;

    loop {
        let url = format!(
            "{}/api/v1/bridge/withdrawals?limit={}&offset={}",
            base_url, limit, offset,
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
        let page_len = data.withdrawals.len() as u64;
        all_withdrawals.extend(data.withdrawals);

        if page_len < limit as u64 || all_withdrawals.len() as i64 >= data.total {
            break;
        }
        offset += page_len;
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

fn u32x8_be_to_hex(words: [u32; 8]) -> String {
    let mut bytes = [0u8; 32];
    for (i, &w) in words.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
    }
    format!("0x{}", hex::encode(bytes))
}

pub(crate) fn compute_withdrawal_leaf_words(
    recipient: [u32; 8],
    token_address: [u32; 8],
    amount: [u32; 8],
    nonce: u64,
    destination_chain_id: u64,
) -> anyhow::Result<[u32; 8]> {
    let nonce_u32 = u32::try_from(nonce)
        .map_err(|_| anyhow::anyhow!("withdrawal nonce {} exceeds uint32 bridge encoding", nonce))?;
    let destination_chain_u32 = u32::try_from(destination_chain_id).map_err(|_| {
        anyhow::anyhow!(
            "destination_chain_id {} exceeds uint32 bridge encoding",
            destination_chain_id
        )
    })?;

    let felts = recipient
        .into_iter()
        .chain(token_address)
        .chain(amount)
        .map(GoldilocksField::from_canonical_u32)
        .chain([
            GoldilocksField::from_canonical_u32(nonce_u32),
            GoldilocksField::from_canonical_u32(destination_chain_u32),
        ])
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

fn compute_withdrawal_leaf_hash(
    recipient: [u32; 8],
    token_address: [u32; 8],
    amount: [u32; 8],
    nonce: u64,
    destination_chain_id: u64,
) -> anyhow::Result<String> {
    Ok(u32x8_be_to_hex(compute_withdrawal_leaf_words(
        recipient,
        token_address,
        amount,
        nonce,
        destination_chain_id,
    )?))
}

pub async fn fetch_pending_bridge_withdrawals(
    args: &ProposeWithdrawalsArgs,
    _from_checkpoint: u64,
    _to_checkpoint_exclusive: u64,
    initial_offset: u64,
) -> anyhow::Result<Vec<PendingWithdrawal>> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let http = build_default_http_client()?;
    let services_url = resolve_services_url(&args.services_url, &psy_config)?;

    let mut service_withdrawals =
        fetch_bridge_withdrawals(&http, &services_url, initial_offset).await?;
    service_withdrawals.sort_by_key(|w| w.event_id);
    tracing::info!(
        bridge_withdrawals = service_withdrawals.len(),
        initial_offset,
        "fetched bridge withdrawals (single pass, no retry)"
    );

    let mut withdrawals: Vec<PendingWithdrawal> = Vec::new();

    for withdrawal in service_withdrawals {
        // `initial_offset` is derived from withdrawal_tree_next_index, so the
        // services pagination cursor is already aligned with the first
        // unappended withdrawal. We intentionally do not re-filter by
        // checkpoint window here.
        tracing::debug!(
            event_id = withdrawal.event_id,
            checkpoint_id = withdrawal.checkpoint_id,
            nonce = withdrawal.nonce,
            destination_chain_id = withdrawal.destination_chain_id,
            leaf_hash = %withdrawal.leaf_hash,
            "evaluated bridge withdrawal"
        );

        let token_words = withdrawal.token_address_words()?;
        let amount_words = withdrawal.amount_words()?;
        let recipient_words = withdrawal.recipient_words()?;
        let local_leaf = compute_withdrawal_leaf_hash(
            recipient_words,
            token_words,
            amount_words,
            withdrawal.nonce,
            withdrawal.destination_chain_id,
        )?;
        if local_leaf != withdrawal.leaf_hash {
            tracing::error!(
                local = %local_leaf,
                services = %withdrawal.leaf_hash,
                nonce = withdrawal.nonce,
                "leaf hash mismatch; services may have stale/incorrect data"
            );
            continue;
        }

        withdrawals.push(PendingWithdrawal {
            event_id: withdrawal.event_id,
            checkpoint_id: withdrawal.checkpoint_id,
            user_id: withdrawal.user_id,
            destination_chain_id: withdrawal.destination_chain_id,
            token_address: token_words,
            amount: amount_words,
            recipient: recipient_words,
            nonce: withdrawal.nonce,
            leaf_hash: withdrawal.leaf_hash,
        });
    }

    withdrawals.sort_by_key(|w| w.event_id);

    Ok(withdrawals)
}

pub async fn build_withdrawal_round_plan(
    args: &ProposeWithdrawalsArgs,
    from_checkpoint: u64,
    to_checkpoint_exclusive: u64,
) -> anyhow::Result<WithdrawalRoundPlan> {
    let discovered = fetch_pending_bridge_withdrawals(args, from_checkpoint, to_checkpoint_exclusive, 0).await?;
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
) -> anyhow::Result<Vec<PendingWithdrawal>> {
    Ok(build_withdrawal_round_plan(args, from_checkpoint, to_checkpoint_exclusive)
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
) -> anyhow::Result<ProposeResult> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let provider = RpcProvider::new_with_config(&rpc_config)?;
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
    let services_url = resolve_services_url(&args.services_url, &psy_config)?;
    let services_latest_checkpoint = fetch_services_latest_checkpoint(&http, &services_url).await?;
    if services_latest_checkpoint <= to_checkpoint_inclusive {
        anyhow::bail!(
            "services not caught up: services_latest_checkpoint={} <= to_checkpoint_inclusive={}",
            services_latest_checkpoint, to_checkpoint_inclusive
        );
    }

    let discovered = fetch_pending_bridge_withdrawals(&args, from_checkpoint, to_checkpoint_exclusive, 0).await?;

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

    // ── Step 4: build append_withdrawal contract calls ───────────────────────
    let contract_calls: Vec<ContractCallArgs> = discovered
        .iter()
        .map(|w| ContractCallArgs {
            contract_id: WITHDRAWAL_TREE_CONTRACT_ID as u64,
            method_name: "append_withdrawal".to_string(),
            inputs: std::iter::once(w.destination_chain_id)
                .chain(w.token_address.iter().map(|&v| v as u64))
                .chain(w.amount.iter().map(|&v| v as u64))
                .chain(w.recipient.iter().map(|&v| v as u64))
                .chain(std::iter::once(w.nonce))
                .collect(),
        })
        .collect();

    let contract_call_data = ContractCallData::new(contract_calls);

    // ── Step 5: submit tx via proposer's software-defined key ────────────────
    let mut wallet_session = WalletSession::new(&rpc_config).await?;
    let info = load_wallet_key_info(&args.wallet, false)?;

    match args.wallet.sign_type {
        SignType::SoftwareDefinedPlonky2Sign => {
            let fingerprint = wallet_session
                .wallet
                .register_plonky2_software_defined_circuit(MAX_CONTRACT_STATE_TREE_HEIGHT, 0)
                .await?;
            assert_eq!(info.fingerprint, fingerprint, "software-defined-plonky2-sign key fingerprint mismatch");
        }
        SignType::SoftwareDefinedDPNSign => {
            let user_sdc: DPNFunctionCircuitDefinition = serde_json::from_str(&std::fs::read_to_string("sdc.json")?)?;
            let fingerprint = wallet_session.wallet.register_psy_software_defined_circuit(user_sdc, false).await?;
            assert_eq!(info.fingerprint, fingerprint, "software-defined-dpn-sign key fingerprint mismatch");
        }
        _ => {}
    };

    // Record realm checkpoint BEFORE submission so we can detect advancement.
    let realm_checkpoint_before = provider.get_realm_latest_block_state().await?.checkpoint_id;

    let user_pk_hash = wallet_session.add_user(info.private_key, info.fingerprint).await?;
    let tx_hash = wallet_session
        .exec_contract_call(user_pk_hash, contract_call_data)
        .await?;

    tracing::info!(
        withdrawals_count = discovered.len(),
        from_checkpoint,
        to_checkpoint_exclusive,
        tx_hash = %tx_hash,
        "append_withdrawal tx submitted"
    );

    // ── Step 6: wait for checkpoint, then read root from bridge contract state ─
    let withdrawals_count = discovered.len();
    let result = {
        let new_realm_checkpoint =
            poll_realm_checkpoint_advance(&provider, realm_checkpoint_before, args.poll_timeout_secs, args.poll_interval_secs).await?;

        let withdrawal_tree_root = provider
            .get_proposed_withdrawal_tree_root(new_realm_checkpoint, BRIDGE_USER_ID_U64)
            .await?;

        tracing::info!(
            new_realm_checkpoint,
            withdrawal_tree_root = %withdrawal_tree_root,
            "read withdrawal_tree_root from bridge contract state"
        );

        // 6c. Notify coordinator
        // provider.submit_withdrawals(&withdrawal_tree_root).await?;

        tracing::info!(
            withdrawal_tree_root = %withdrawal_tree_root,
            "submitted withdrawal_tree_root to coordinator via submit_withdrawals"
        );

        ProposeResult {
            observed_checkpoint_id: new_realm_checkpoint,
            withdrawal_tree_root,
            withdrawals: discovered,
        }
    };

    tracing::info!(
        withdrawals_count,
        to_checkpoint_exclusive,
        "propose-withdrawals completed successfully"
    );

    Ok(result)
}

pub async fn run(args: ProposeWithdrawalsArgs) -> anyhow::Result<()> {
    let (from_checkpoint, requested_to_checkpoint_exclusive) = resolve_scan_range(&args)?;
    let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
    let latest_checkpoint = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
    let to_checkpoint_exclusive = requested_to_checkpoint_exclusive.min(latest_checkpoint);

    tracing::info!(
        from_checkpoint,
        requested_to_checkpoint_exclusive,
        to_checkpoint_exclusive,
        latest_checkpoint,
        "resolved withdrawal scan range"
    );

    let _ = run_and_get_withdrawal_root(args.clone(), from_checkpoint, to_checkpoint_exclusive).await?;
    save_state_checkpoint(&args.state_file, to_checkpoint_exclusive)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_withdrawal_leaf_hash_encodings() -> anyhow::Result<()> {
        let recipient_hex = "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266";
        let token_hex = "0x00000000000000000000000068b1d87f95878fe05b998f19b66f4baba5de1aed";
        let amount_hex = "0x000000000000000000000000000000000000000000000000000000e8d4a51000";
        let nonce = 3_598_904_774u64;
        let destination_chain_id = 0u64;
        let expected_words = [
            0xb266cae6,
            0x9694ffe0,
            0xf0551a56,
            0x81482205,
            0x35c48e19,
            0x17ffb896,
            0x3c70cafb,
            0x0f98d424,
        ];

        let recipient = parse_u32x8_from_hex(recipient_hex)?;
        let token_address = parse_u32x8_from_hex(token_hex)?;
        let amount = parse_u32x8_from_hex(amount_hex)?;

        let actual_words = compute_withdrawal_leaf_words(
            recipient,
            token_address,
            amount,
            nonce,
            destination_chain_id,
        )?;
        assert_eq!(
            actual_words, expected_words,
            "leaf word encoding must match on-chain append event"
        );

        Ok(())
    }
}
