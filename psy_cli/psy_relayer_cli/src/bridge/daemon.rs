use std::{
    collections::{HashMap, HashSet},
    env,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use futures::stream::{FuturesUnordered, StreamExt};

use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::{BlockNumberOrTag, Filter, TransactionRequest};
use alloy_sol_types::{SolCall, SolEvent, sol};
use anyhow::{Context, ensure};
use clap::Args;
use gnark_plonky2_verifier_ffi as g16;
use psy_client_common::args::{SignType, WalletSourceArgs};
use psy_client_common::args::{ContractCallArgs, ContractCallData};
use psy_client_common::data::qhashout::QHashOut;
use psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT;
use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
use psy_core::constants::chain_id::PsyChainNetworkType;

use psy_prover::session::WalletSession;
use psy_provider::provider::RpcProvider;
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;
use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};
use serde::{Deserialize, Serialize};

use psy_cli_common::key_utils::load_wallet_key_info;
use crate::bridge::{
    compute_deposit_leaf::{self, ComputeDepositLeafArgs},
    claim_withdrawals,
    constants::{
        BRIDGE_USER_ID_U64, DEFAULT_DEPLOYMENTS_NETWORK, DEFAULT_L1_RPC_URL, DEPOSIT_TREE_CONTRACT_ID, WITHDRAWAL_TREE_CONTRACT_ID,
        L1_GROTH16_CALL_GAS_FALLBACK, L1_MULTICALL_GAS_BUDGET,
        REALM_CHECKPOINT_POLL_INTERVAL_SECS, REALM_CHECKPOINT_POLL_TIMEOUT_SECS, DEFAULT_SDC_PATH,
    },
    finalize_bridge::{self, FinalizeBridgeAggArgs},
    l1_client::L1Client,
    l1_signer::load_l1_wallet,
    propose_withdrawals::{self, ProposeResult, ProposeWithdrawalsArgs},
    prove_bridge::{self, BridgeProveResult},
};

const DEFAULT_PROOF_DIR: &str = "/tmp/psy_bridge_proofs";
const CONTRACT_STATE_TREE_HEIGHT: u8 = 32;
const DEFAULT_MAX_CHECKPOINT_BATCH: u64 = 32;
const NETWORK_TYPE: PsyChainNetworkType = PsyChainNetworkType::LocalDevnet;
sol! {
    struct Call3 {
        address target;
        bool allowFailure;
        bytes callData;
    }

    struct Aggregate3Result {
        bool success;
        bytes returnData;
    }

    function aggregate3(
        Call3[] calls
    ) payable returns (Aggregate3Result[] returnData);

    function provedDepositCount() external view returns (uint256);
    function pendingDepositCount() external view returns (uint256);
    function lastFinalizedCheckpointId() external view returns (uint64);
}

#[derive(Clone, Args)]
pub struct RunDaemonArgs {
    #[arg(long)]
    pub config: PathBuf,
}

#[derive(Clone, Deserialize)]
pub(crate) struct BridgeProposeDaemonConfig {
    pub rpc_config: String,
    pub services_url: String,
    pub withdraw_method_id: u64,
    pub proof_dir: Option<PathBuf>,
    pub poll_interval_secs: Option<u64>,
    #[serde(default)]
    pub confirmation_lag_checkpoints: Option<u64>,
    #[serde(default)]
    pub max_checkpoint_batch: Option<u64>,
    pub withdrawal_scan_lookback_checkpoints: Option<u64>,
    #[serde(default)]
    pub relayer_wallet: Option<WalletSourceArgs>,
    #[serde(default, alias = "propose_wallet")]
    pub append_wallet: Option<WalletSourceArgs>,
    #[serde(default)]
    pub finalize: DaemonFinalizeConfig,
    /// Max concurrent L2 batch submissions (for buffered_unordered).
    /// Default=1 (sequential). Set >1 to enable concurrent batch dispatch.
    #[serde(default)]
    pub max_concurrent_l2_batches: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct DaemonFinalizeConfig {
    pub l1_rpc_url: Option<String>,
    pub l1_rpc_fallback_url: Option<String>,
    pub deployments_network: Option<String>,
    pub state_manager: Option<String>,
    pub bridge_address: Option<String>,
    pub bridge: Option<String>,
    pub private_key: Option<String>,
    pub keystore_path: Option<String>,
    pub password_env: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct DaemonState {
    last_finalized_checkpoint: u64,
    /// Withdrawals that still need a successful L1 claim.
    ///
    /// This set is the single source of truth for crash recovery:
    /// newly-scanned withdrawals are inserted before finalize/claim,
    /// successful claims remove entries, and all remaining entries are
    /// retried next round. The key is leaf_hash.
    #[serde(default, alias = "failed_claim_withdrawals")]
    pending_claim_withdrawals: HashMap<String, propose_withdrawals::PendingWithdrawal>,
}

async fn create_wallet_session(
    config: &BridgeProposeDaemonConfig,
) -> anyhow::Result<(WalletSession, psy_client_common::data::qhashout::QHashOut<GoldilocksField>)> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&config.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let wallet_args = resolve_bridge_wallet_args(config.append_wallet.clone().or(config.relayer_wallet.clone()));
    let mut wallet_session = WalletSession::new(&rpc_config).await?;
    let info = load_wallet_key_info(&wallet_args, false)?;
    match wallet_args.sign_type {
        SignType::SoftwareDefinedPlonky2Sign => {
            let fingerprint = wallet_session
                .wallet
                .register_plonky2_software_defined_circuit(MAX_CONTRACT_STATE_TREE_HEIGHT, 0)
                .await?;
            assert_eq!(info.fingerprint, fingerprint, "software-defined-plonky2-sign key fingerprint mismatch");
        }
        SignType::SoftwareDefinedDPNSign => {
            let user_sdc: DPNFunctionCircuitDefinition =
                serde_json::from_str(&std::fs::read_to_string(DEFAULT_SDC_PATH)?)?;
            let fingerprint = wallet_session
                .wallet
                .register_psy_software_defined_circuit(user_sdc, false)
                .await?;
            assert_eq!(info.fingerprint, fingerprint, "software-defined-dpn-sign key fingerprint mismatch");
        }
        _ => {}
    };
    let user_pk_hash = wallet_session.add_user(info.private_key, info.fingerprint).await?;
    Ok((wallet_session, user_pk_hash))
}

fn resolve_bridge_wallet_args(args: Option<WalletSourceArgs>) -> WalletSourceArgs {
    let mut wallet_args = args.unwrap_or(WalletSourceArgs {
        sign_type: SignType::ZKSign,
        private_key: None,
        keystore_path: None,
        wallet_password: None,
        fingerprint: None,
        sdk_key_allowed_contract_id: vec![],
        sdk_key_allowed_method_id: vec![],
        sdk_key_expected_tx_count: 2,
    });
    if wallet_args.keystore_path.is_none() {
        wallet_args.keystore_path = env::var("KEYSTORE_PATH").ok().filter(|v| !v.trim().is_empty());
    }
    if wallet_args.wallet_password.is_none() {
        wallet_args.wallet_password = env::var("WALLET_PASSWORD").ok().filter(|v| !v.trim().is_empty());
    }
    if wallet_args.private_key.is_none() && wallet_args.keystore_path.is_none() {
        wallet_args.private_key = env::var("PRIVATE_KEY")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| env::var("BRIDGE_RELAYER_L2_PRIVATE_KEY").ok().filter(|v| !v.trim().is_empty()));
    }
    wallet_args
}

#[derive(Clone, Debug)]
struct DepositAppendCall {
    deposit_index: u32,
    chain_index: u32,
    leaf_hex: String,
    leaf_words: [u32; 8],
}

#[derive(Debug)]
pub(crate) struct L2RoundResult {
    deposits_consumed: u64,
    to_checkpoint: u64,
    submitted_l2_work: bool,
    
    claim_withdrawals: Vec<propose_withdrawals::PendingWithdrawal>,
}

#[derive(Debug)]
struct L2CallPlan {
    deposit_range: Option<(u32, u32)>,
    withdrawals: Vec<propose_withdrawals::PendingWithdrawal>,
    /// Optimized batch calls using batch_2/batch_5 or individual methods.
    /// Each element is ONE ContractCallArgs for a batch (or single).
    batch_calls: Vec<ContractCallArgs>,
}

impl L2CallPlan {
    fn is_empty(&self) -> bool {
        self.batch_calls.is_empty()
    }
    fn has_withdrawals(&self) -> bool {
        !self.withdrawals.is_empty() && self.withdrawals.iter().any(|w| w.leaf_hash != "0")
    }
}

// ── Batch packing utilities ──────────────────────────────────────────────────

/// Compute optimal batch sizes for N items using sizes 1, 2, 5.
/// Minimizes total batch count while keeping x<2, y<5.
fn optimal_batch_sizes(n: usize) -> Vec<usize> {
    if n == 0 {
        return Vec::new();
    }
    let mut best_total = usize::MAX;
    let mut best = (0usize, 0usize, 0usize);
    for fives in 0..=n / 5 {
        let rem = n - fives * 5;
        for twos in 0..=rem / 2 {
            let singles = rem - twos * 2;
            if singles < 2 {
                let total = singles + twos + fives;
                if total < best_total {
                    best_total = total;
                    best = (singles, twos, fives);
                }
            }
        }
    }
    let (singles, twos, fives) = best;
    let mut sizes = Vec::with_capacity(singles + twos + fives);
    for _ in 0..singles {
        sizes.push(1);
    }
    for _ in 0..twos {
        sizes.push(2);
    }
    for _ in 0..fives {
        sizes.push(5);
    }
    sizes
}

/// Build optimized batch `ContractCallArgs` for deposit appends.
/// Preserves original order, packs via optimal_batch_sizes.
/// All deposits in a round share the same chain_index.
fn build_deposit_batch_calls(
    deposit_calls: &[DepositAppendCall],
) -> Vec<ContractCallArgs> {
    if deposit_calls.is_empty() {
        return Vec::new();
    }
    let mut calls = Vec::new();
    let n = deposit_calls.len();
    // All deposits in this round share chain_index from first item.
    // Contract: append_deposit(chain_index: Felt, leaf: [u32; 8])
    //          batch_append_deposits_2(chain_index: Felt, count: Felt, leaf_data: [u32; 16])
    //          batch_append_deposits_5(chain_index: Felt, count: Felt, leaf_data: [u32; 40])
    let chain_index = deposit_calls[0].chain_index as u64;
    let sizes = optimal_batch_sizes(n);
    let mut pos = 0;
    for &chunk_size in &sizes {
        match chunk_size {
            1 => {
                let d = &deposit_calls[pos];
                let mut inputs = vec![chain_index];
                inputs.extend(d.leaf_words.iter().map(|&v| v as u64));
                calls.push(ContractCallArgs {
                    contract_id: DEPOSIT_TREE_CONTRACT_ID as u64,
                    method_name: "append_deposit".to_string(),
                    inputs,
                });
            }
            2 | 5 => {
                let method = if chunk_size == 2 {
                    "batch_append_deposits_2"
                } else {
                    "batch_append_deposits_5"
                };
                let mut inputs = vec![chain_index, chunk_size as u64];
                for k in 0..chunk_size {
                    inputs.extend(deposit_calls[pos + k].leaf_words.iter().map(|&v| v as u64));
                }
                calls.push(ContractCallArgs {
                    contract_id: DEPOSIT_TREE_CONTRACT_ID as u64,
                    method_name: method.to_string(),
                    inputs,
                });
            }
            _ => unreachable!(),
        }
        pos += chunk_size;
    }
    calls
}

/// Build optimized batch `ContractCallArgs` for withdrawal appends.
/// New batch interface: batch_append_withdrawals_N(count, chain_indices, leaf_data).
/// Each leaf carries its own destination_chain_index, letting mixed-chain
/// withdrawals share a single batch call.
fn build_withdrawal_batch_calls(
    withdrawals: &[propose_withdrawals::PendingWithdrawal],
) -> Vec<ContractCallArgs> {
    if withdrawals.is_empty() {
        return Vec::new();
    }

    // Pre-compute leaf hashes (index-aligned with withdrawals)
    let leaf_hashes: Vec<[u32; 8]> = withdrawals
        .iter()
        .map(|w| {
            propose_withdrawals::compute_withdrawal_leaf_words(
                w.recipient,
                w.token_address,
                w.amount,
                w.nonce,
                w.destination_chain_id,
            )
        })
        .collect::<anyhow::Result<Vec<_>>>()
        .expect("withdrawal leaf hash computation failed");

    let mut calls = Vec::new();
    let sizes = optimal_batch_sizes(withdrawals.len());
    let mut pos = 0;
    for &chunk_size in &sizes {
        match chunk_size {
            1 => {
                let w = &withdrawals[pos];
                let mut inputs = vec![w.destination_chain_id];
                inputs.extend(w.token_address.iter().map(|&v| v as u64));
                inputs.extend(w.amount.iter().map(|&v| v as u64));
                inputs.extend(w.recipient.iter().map(|&v| v as u64));
                inputs.push(w.nonce);
                calls.push(ContractCallArgs {
                    contract_id: WITHDRAWAL_TREE_CONTRACT_ID as u64,
                    method_name: "append_withdrawal".to_string(),
                    inputs,
                });
            }
            2 | 5 => {
                let method = if chunk_size == 2 {
                    "batch_append_withdrawals_2"
                } else {
                    "batch_append_withdrawals_5"
                };
                // New encoding: count, chain_indices[N], leaf_data[N*8]
                let mut inputs = vec![chunk_size as u64];
                // chain_indices
                for k in 0..chunk_size {
                    inputs.push(withdrawals[pos + k].destination_chain_id);
                }
                // leaf_data
                for k in 0..chunk_size {
                    inputs.extend(leaf_hashes[pos + k].iter().map(|&v| v as u64));
                }
                calls.push(ContractCallArgs {
                    contract_id: WITHDRAWAL_TREE_CONTRACT_ID as u64,
                    method_name: method.to_string(),
                    inputs,
                });
            }
            _ => unreachable!(),
        }
        pos += chunk_size;
    }
    calls
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RelayerWindow {
    to_checkpoint: u64,
    confirmed_to_checkpoint: Option<u64>,
    is_catchup_batch: bool,
}

impl RelayerWindow {
    fn has_confirmed_range(self) -> bool {
        self.confirmed_to_checkpoint.is_some()
    }
}

fn select_relayer_window(
    from_checkpoint: u64,
    latest_checkpoint: u64,
    confirmation_lag_checkpoints: u64,
    max_checkpoint_batch: u64,
) -> RelayerWindow {
    let confirmed_to_checkpoint = latest_checkpoint.checked_sub(confirmation_lag_checkpoints);
    let Some(confirmed_to_checkpoint) = confirmed_to_checkpoint.filter(|confirmed| *confirmed >= from_checkpoint) else {
        let catchup_to = if max_checkpoint_batch == 0 {
            latest_checkpoint
        } else {
            latest_checkpoint.min(from_checkpoint.saturating_add(max_checkpoint_batch.saturating_sub(1)))
        };
        return RelayerWindow {
            to_checkpoint: catchup_to,
            confirmed_to_checkpoint: None,
            is_catchup_batch: false,
        };
    };

    let to_checkpoint = if max_checkpoint_batch == 0 {
        confirmed_to_checkpoint
    } else if confirmed_to_checkpoint - from_checkpoint + 1 > max_checkpoint_batch {
        // Landed window exceeds max_checkpoint_batch — use full range to trigger
        // multi-chunk bridge aggregation (bridge_agg_chain + bridge_agg_final).
        confirmed_to_checkpoint
    } else {
        let batch_end = from_checkpoint.saturating_add(max_checkpoint_batch.saturating_sub(1));
        confirmed_to_checkpoint.min(batch_end)
    };

    RelayerWindow {
        to_checkpoint,
        confirmed_to_checkpoint: Some(confirmed_to_checkpoint),
        is_catchup_batch: to_checkpoint < confirmed_to_checkpoint,
    }
}

pub async fn run(args: RunDaemonArgs) -> anyhow::Result<()> {
    let config = load_config(&args.config)?;
    let proof_dir = config
        .proof_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PROOF_DIR));
    fs::create_dir_all(&proof_dir).with_context(|| format!("failed to create proof dir {}", proof_dir.display()))?;
    tracing::info!(config = %args.config.display(), proof_dir = %proof_dir.display(), "bridge relayer started");

    // Phase 4.4: skip local circuit/Groth16 warmup when remote prove proxy is configured
    let proxy_url_at_startup = resolve_prove_proxy_url(&config);
    if proxy_url_at_startup.is_some() {
        tracing::info!("prove proxy configured; skipping local circuit/Groth16 warmup");
    } else {
        warmup_bridge_resources()?;
    }

    let provider = RpcProvider::new_with_config_path(&config.rpc_config)?;
    let l1 = L1Client::from_finalize_config(&config.finalize);
    let bridge_address = resolve_bridge_address(&config)?;
    let bridge = bridge_address
        .parse::<Address>()
        .context("invalid bridge address in daemon config")?;
    let state_manager = resolve_state_manager_address(&config)?;
    let poll_interval = Duration::from_secs(config.poll_interval_secs.unwrap_or(30));
    let confirmation_lag_checkpoints = config.confirmation_lag_checkpoints.unwrap_or(3);
    let max_checkpoint_batch = config.max_checkpoint_batch.unwrap_or(DEFAULT_MAX_CHECKPOINT_BATCH);
    let state_path = proof_dir.join("daemon_state.toml");

    loop {
        let mut state = load_state(&state_path)?;
        match l1.last_finalized_checkpoint(state_manager).await {
            Ok(l1_last_finalized_checkpoint) => {
                state = reconcile_state_with_l1_finalized_checkpoint(
                    state,
                    &state_path,
                    l1_last_finalized_checkpoint,
                )?;
            }
            Err(err) => {
                tracing::error!(
                    state_manager = %state_manager,
                    error = %err,
                    "failed to read L1 StateManager finalization cursor; retrying before starting next relayer round"
                );
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        //  CHECKPOINT WINDOW ── pre-round state check
        // ═══════════════════════════════════════════════════════════════════

        let from_checkpoint = state.last_finalized_checkpoint + 1;
        let latest_checkpoint = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
        tracing::info!(
            from_checkpoint,
            latest_checkpoint,
            confirmation_lag_checkpoints,
            last_finalized_checkpoint = state.last_finalized_checkpoint,
            "pre-round: checkpoint window"
        );
        let window = select_relayer_window(
            from_checkpoint,
            latest_checkpoint,
            confirmation_lag_checkpoints,
            max_checkpoint_batch,
        );
        let to_checkpoint = window.to_checkpoint;
        let is_catchup_batch = window.is_catchup_batch;
        let propose_args = ProposeWithdrawalsArgs {
            rpc_config: config.rpc_config.clone(),
            wallet: resolve_bridge_wallet_args(config.relayer_wallet.clone()),
            services_url: Some(config.services_url.clone()),
            withdraw_method_id: config.withdraw_method_id,
            state_file: None,
            notify_coordinator: true,
            poll_timeout_secs: 120,
            poll_interval_secs: 5,
        };

        let round_mode = if window.has_confirmed_range() { "ROUND" } else { "APPEND-ONLY" };
        tracing::info!(
            from_checkpoint,
            to_checkpoint,
            latest_checkpoint,
            confirmed_to_checkpoint = window.confirmed_to_checkpoint,
            max_checkpoint_batch,
            is_catchup_batch,
            "[bridge-{}] phase1: L2 bridge (append deposits + withdrawals to L2)",
            round_mode,
        );

        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 1 ─ L2 Bridge Round (append deposits + withdrawals to L2)
        // ═══════════════════════════════════════════════════════════════════

        let l2_round = match l1.run_l2_bridge_round(
            &config,
            &provider,
            bridge,
            from_checkpoint,
            to_checkpoint,
            confirmation_lag_checkpoints,
            !is_catchup_batch,
            window.has_confirmed_range(),
            &state,
            propose_args.clone(),
        )
        .await
        {
            Ok(result) => result,
            Err(err) => {
                tracing::error!(
                    from_checkpoint,
                    latest_checkpoint,
                    to_checkpoint,
                    error = %err,
                    "bridge daemon run_l2_bridge_round failed"
                );
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };

        if !window.has_confirmed_range() && !l2_round.submitted_l2_work {
            tracing::info!(
                from_checkpoint,
                to_checkpoint = l2_round.to_checkpoint,
                latest_checkpoint,
                deposits_consumed = l2_round.deposits_consumed,
                "[bridge-APPEND-ONLY] no deposits to append; idle poll"
            );
            tokio::time::sleep(poll_interval).await;
            continue;
        }

        let to_checkpoint = l2_round.to_checkpoint;
        let proof_path = proof_dir.join(format!("bridge_proof_{}.json", to_checkpoint));
        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 2 ─ Deposit Batch Appends (submit Groth16 proof to L1)
        // ═══════════════════════════════════════════════════════════════════

        if l2_round.deposits_consumed > 0 {
            if let Err(err) = l1.submit_deposit_batch_appends(&config, l2_round.deposits_consumed).await {
                tracing::error!(
                    to_checkpoint,
                    deposits_consumed = l2_round.deposits_consumed,
                    error = %err,
                    "bridge daemon deposit batchAppend step failed"
                );
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 3 ─ Proof Generation (bridge aggregation + Groth16 wrap)
        // ═══════════════════════════════════════════════════════════════════

        let prove_proxy_url = resolve_prove_proxy_url(&config);
        let prove_result = match l1.load_or_build_proof(
            &config,
            &proof_path,
            from_checkpoint,
            to_checkpoint,
            l2_round.deposits_consumed,
            prove_proxy_url.as_deref(),
        )
        .await
        {
            Ok(result) => result,
            Err(err) => {
                tracing::error!(to_checkpoint, error = %err, "bridge daemon prove step failed");
                let _ = fs::remove_file(&proof_path);
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };

        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 4 ─ Finalize + Claim Withdrawals (submit to L1 StateManager)
        // ═══════════════════════════════════════════════════════════════════

        let finalize_args = FinalizeBridgeAggArgs {
            proof_json: proof_path.clone(),
            to_checkpoint,
            rpc_config: config.rpc_config.clone(),
            l1_rpc_url: config
                .finalize
                .l1_rpc_url
                .clone()
                .unwrap_or_else(|| DEFAULT_L1_RPC_URL.to_string()),
            deployments_network: config
                .finalize
                .deployments_network
                .clone()
                .unwrap_or_else(|| DEFAULT_DEPLOYMENTS_NETWORK.to_string()),
            state_manager: config.finalize.state_manager.clone(),
            bridge_address: Some(bridge_address.clone()),
            batch_append_proof_json: None,
            private_key: config.finalize.private_key.clone(),
            keystore_path: config.finalize.keystore_path.clone().map(PathBuf::from),
            password_env: config
                .finalize
                .password_env
                .clone()
                .unwrap_or_else(|| "WALLET_PASSWORD".to_string()),
            deposits_consumed: prove_result.deposits_consumed as u32,
        };

        let withdrawal_count = l2_round.claim_withdrawals.len();
        let current_round_withdrawals = l2_round.claim_withdrawals;
        let mut pending_claim_withdrawals = state.pending_claim_withdrawals.clone();
        for withdrawal in &current_round_withdrawals {
            pending_claim_withdrawals
                .entry(withdrawal.leaf_hash.clone())
                .or_insert_with(|| withdrawal.clone());
        }
        if let Err(e) = save_state(
            &state_path,
            &DaemonState {
                last_finalized_checkpoint: state.last_finalized_checkpoint,
                pending_claim_withdrawals: pending_claim_withdrawals.clone(),
            },
        ) {
            tracing::error!(error = %e, "failed to persist pending claims before finalize");
        }

        match l1.finalize(finalize_args).await {
            Ok(()) => {
                // Brief pause to ensure L1 state is settled before gas
                // estimation for the claim transaction.
                tokio::time::sleep(Duration::from_secs(2)).await;
                let to_claim: Vec<propose_withdrawals::PendingWithdrawal> =
                    pending_claim_withdrawals.values().cloned().collect();

                if to_claim.is_empty() {
                    tracing::info!(
                        to_checkpoint,
                        withdrawal_count,
                        "no withdrawals pending claim; advancing claim cursor"
                    );
                } else {
                    match l1.claim_withdrawals(&to_claim, &config, to_checkpoint).await {
                        Ok(report) => {
                            apply_claim_report(&mut pending_claim_withdrawals, &report);
                            if report.failure_reasons.is_empty() {
                                tracing::info!(
                                    to_checkpoint,
                                    requested = report.requested,
                                    submitted_count = report.submitted_count,
                                    already_claimed_count = report.already_claimed_count,
                                    resolved = report.resolved_leaf_hashes.len(),
                                    failed = report.failure_reasons.len(),
                                    pending_claims = pending_claim_withdrawals.len(),
                                    "withdrawal claims finished"
                                );
                            } else {
                                tracing::warn!(
                                    to_checkpoint,
                                    requested = report.requested,
                                    submitted_count = report.submitted_count,
                                    already_claimed_count = report.already_claimed_count,
                                    resolved = report.resolved_leaf_hashes.len(),
                                    failed = report.failure_reasons.len(),
                                    pending_claims = pending_claim_withdrawals.len(),
                                    "withdrawal claims finished with pending retries"
                                );
                            }
                        }
                        Err(err) => {
                            tracing::error!(
                                to_checkpoint,
                                error = %err,
                                pending_claims = pending_claim_withdrawals.len(),
                                "withdrawal claims failed; keeping pending set for retry"
                            );
                        }
                    }
                }

                if let Err(e) = save_state(
                    &state_path,
                    &DaemonState {
                        last_finalized_checkpoint: to_checkpoint,
                        pending_claim_withdrawals,
                    },
                ) {
                    tracing::error!(error = %e, "failed to persist state at end of round");
                }
                let _ = fs::remove_file(&proof_path);
                tracing::info!(
                    to_checkpoint,
                    has_deposits = l2_round.deposits_consumed > 0,
                    submitted_l2_work = l2_round.submitted_l2_work,
                    withdrawal_count,
                    deposits_consumed = l2_round.deposits_consumed,
                    "[bridge-ROUND] phase4 done: finalize + claims complete, checkpoint={}",
                    to_checkpoint,
                );
            }
            Err(err) => {
                tracing::error!(
                    from_checkpoint,
                    to_checkpoint,
                    error = ?err,
                    "bridge daemon finalize step failed"
                );
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        //  ROUND COMPLETE ── sleep before next iteration
        // ═══════════════════════════════════════════════════════════════════

        let final_round_mode = if window.has_confirmed_range() { "ROUND" } else { "APPEND-ONLY" };
        tracing::info!(
            round_mode = final_round_mode,
            from_checkpoint,
            to_checkpoint,
            "[bridge-{}] ── poll-sleep {}s ──",
            final_round_mode,
            poll_interval.as_secs(),
        );

        tokio::time::sleep(poll_interval).await;
    }
}

pub(crate) async fn submit_deposit_batch_appends_with_l1_rpc(
    config: &BridgeProposeDaemonConfig,
    l1_rpc: &str,
    deposits_consumed: u64,
    prove_proxy_url: Option<&str>,
) -> anyhow::Result<()> {
    let deployments_network = config
        .finalize
        .deployments_network
        .as_deref()
        .unwrap_or(DEFAULT_DEPLOYMENTS_NETWORK);
    let bridge = resolve_bridge_address(config)?
        .parse::<Address>()
        .context("invalid bridge address in daemon config")?;
    let multicall3 = claim_withdrawals::resolve_multicall3_address(None, deployments_network)?
        .ok_or_else(|| anyhow::anyhow!("Multicall3 address is required for deposit batchAppend"))?;

    let wallet = load_l1_wallet(
        config.finalize.private_key.as_deref(),
        config.finalize.keystore_path.as_deref().map(Path::new),
        config.finalize.password_env.as_deref(),
        None,
        "L1 deposit batchAppend signer",
    )?;
    let rpc_url = l1_rpc
        .parse()
        .with_context(|| format!("invalid L1 rpc url: {}", l1_rpc))?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);
    let proved_before = crate::bridge::api_client::eth_call_u256(&provider, bridge, provedDepositCountCall {}).await?;
    let expected_proved_after = proved_before + U256::from(deposits_consumed);

    let calls = if let Some(proxy_url) = prove_proxy_url {
        prove_bridge::build_deposit_batch_append_calls_remote(
            l1_rpc,
            deployments_network,
            deposits_consumed,
            proxy_url,
        )
        .await?
    } else {
        prove_bridge::build_deposit_batch_append_calls(
            l1_rpc,
            deployments_network,
            deposits_consumed,
        )
        .await?
    };
    if calls.is_empty() {
        return Ok(());
    }

    let aggregate_chunks = chunk_deposit_batch_append_by_gas(
        &provider,
        multicall3,
        calls
            .iter()
            .map(|call| Call3 {
                target: bridge,
                allowFailure: false,
                callData: call.call_data.clone(),
            })
            .collect(),
    )
    .await; 
    let aggregate_chunk_count = aggregate_chunks.len();
    let aggregate_chunk_count = aggregate_chunks.len();

    for (chunk_index, aggregate_calls) in aggregate_chunks.into_iter().enumerate() {
        let chunk_len = aggregate_calls.len();
        let deposit_batch_commits = calls
            .iter()
            .map(|call| {
                format!(
                    "0x{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
                    call.batch_commit[0],
                    call.batch_commit[1],
                    call.batch_commit[2],
                    call.batch_commit[3],
                    call.batch_commit[4],
                    call.batch_commit[5],
                    call.batch_commit[6],
                    call.batch_commit[7],
                )
            })
            .collect::<Vec<_>>();
        let aggregate = aggregate3Call {
            calls: aggregate_calls,
        };
        let tx = TransactionRequest::default()
            .to(multicall3)
            .input(Bytes::from(aggregate.abi_encode()).into());

        if let Err(err) = provider.call(tx.clone()).await {
            tracing::error!(
                error = ?err,
                chunk_index,
                chunk_len,
                aggregate_chunk_count,
                deposit_batch_chunks = calls.len(),
                deposits_consumed,
                proved_before = %proved_before,
                expected_proved_after = %expected_proved_after,
                deposit_batch_commits = ?deposit_batch_commits,
                multicall3 = %multicall3,
                bridge = %bridge,
                "deposit batchAppend aggregate3 simulation failed"
            );
            return Err(err).context("deposit batchAppend aggregate3 simulation failed");
        }
        tracing::info!(
            chunk_index,
            chunk_len,
            aggregate_chunk_count,
            deposit_batch_chunks = calls.len(),
            deposits_consumed,
            proved_before = %proved_before,
            expected_proved_after = %expected_proved_after,
            multicall3 = %multicall3,
            allow_failure = false,
            "sending deposit batchAppend aggregate3 tx"
        );

        let pending = provider
            .send_transaction(tx)
            .await
            .context("send deposit batchAppend aggregate3 transaction failed")?;
        let receipt = pending
            .get_receipt()
            .await
            .context("wait deposit batchAppend aggregate3 receipt failed")?;
        ensure!(
            receipt.status(),
            "deposit batchAppend aggregate3 transaction reverted: tx_hash={}",
            receipt.transaction_hash
        );
        tracing::info!(
            tx_hash = %receipt.transaction_hash,
            block_number = ?receipt.block_number,
            chunk_index,
            chunk_len,
            aggregate_chunk_count,
            "deposit batchAppend aggregate3 chunk confirmed"
        );
    }

    let proved_after = crate::bridge::api_client::eth_call_u256(&provider, bridge, provedDepositCountCall {}).await?;
    ensure!(
        proved_after == expected_proved_after,
        "Bridge provedDepositCount mismatch after deposit batchAppend aggregate3: expected={} actual={}",
        expected_proved_after,
        proved_after
    );
    tracing::info!(
        deposit_batch_chunks = calls.len(),
        aggregate_chunk_count,
        proved_after = %proved_after,
        "deposit batchAppend aggregate3 confirmed"
    );
    Ok(())
}

fn warmup_bridge_resources() -> anyhow::Result<()> {
    tracing::info!("warming bridge relayer resources");

    prove_bridge::cached_bridge_coordinator_circuits()?;

    let home_dir = home::home_dir().context("failed to resolve home directory for bridge relayer warmup")?;
    let keystores = [
        home_dir.join(".psy/keystore"),
        home_dir.join(".psy/keystore/deposit_append"),
        home_dir.join(".psy/keystore/withdrawal_claim"),
    ];

    for keystore in &keystores {
        if !keystore.join("circuit_groth16.bin").exists()
            || !keystore.join("pk_groth16.bin").exists()
            || !keystore.join("vk_groth16.bin").exists()
        {
            tracing::warn!(keystore = %keystore.display(), "skipping Groth16 warmup because keystore is missing");
            continue;
        }
        let keystore_str = keystore
            .to_str()
            .with_context(|| format!("non-utf8 keystore path: {}", keystore.display()))?;
        tracing::info!(keystore = %keystore.display(), "preloading Groth16 setup");
        g16::initialize(keystore_str);
    }

    tracing::info!("bridge relayer warmup complete");
    Ok(())
}

pub(crate) fn resolve_prove_proxy_url(config: &BridgeProposeDaemonConfig) -> Option<String> {
    let rpc_config = psy_config::PsyConfigGoldilocks::from_file(&config.rpc_config).ok()?;
    let network = rpc_config.get_current_network().ok()?;
    network
        .prove_proxy_url
        .iter()
        .find(|url| !url.trim().is_empty())
        .cloned()
}

fn load_config(path: &Path) -> anyhow::Result<BridgeProposeDaemonConfig> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read daemon config {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("failed to parse daemon config {}", path.display()))
}

fn load_state(path: &Path) -> anyhow::Result<DaemonState> {
    if !path.exists() {
        return Ok(DaemonState::default());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read daemon state {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("failed to parse daemon state {}", path.display()))
}

fn save_state(path: &Path, state: &DaemonState) -> anyhow::Result<()> {
    let raw = toml::to_string(state).context("failed to serialize daemon state")?;
    fs::write(path, raw).with_context(|| format!("failed to write daemon state {}", path.display()))
}

fn reconcile_state_with_l1_finalized_checkpoint(
    mut state: DaemonState,
    state_path: &Path,
    l1_last_finalized_checkpoint: u64,
) -> anyhow::Result<DaemonState> {
    let original_last_finalized = state.last_finalized_checkpoint;

    state.last_finalized_checkpoint = l1_last_finalized_checkpoint;

    if state.last_finalized_checkpoint != original_last_finalized
    {
        tracing::warn!(
            local_last_finalized_checkpoint = original_last_finalized,
            l1_last_finalized_checkpoint,
            pending_claims = state.pending_claim_withdrawals.len(),
            "reconciled bridge daemon state with L1 StateManager"
        );
        if let Err(e) = save_state(state_path, &state) {
            tracing::error!(error = %e, "failed to persist reconciled state");
        }
    }

    Ok(state)
}

pub(crate) async fn fetch_l1_last_finalized_checkpoint(
    provider: &impl Provider,
    state_manager: Address,
) -> anyhow::Result<u64> {
    let tx = TransactionRequest::default()
        .to(state_manager)
        .input(lastFinalizedCheckpointIdCall {}.abi_encode().into());
    let raw = provider
        .call(tx)
        .await
        .context("StateManager.lastFinalizedCheckpointId eth_call failed")?;
    lastFinalizedCheckpointIdCall::abi_decode_returns(&raw)
        .context("failed to decode StateManager.lastFinalizedCheckpointId return")
}

fn deposit_tree_next_index(next_index_slot: psy_client_common::data::qhashout::QHashOut<GoldilocksField>) -> anyhow::Result<u64> {
    let next_index = next_index_slot.0.elements[0].to_canonical_u64();
    ensure!(
        next_index <= u32::MAX as u64,
        "deposit tree next_index exceeds u32 range: {}",
        next_index
    );
    Ok(next_index)
}

pub(crate) fn resolve_bridge_address(config: &BridgeProposeDaemonConfig) -> anyhow::Result<String> {
    if let Some(addr) = config.finalize.bridge_address.as_deref() {
        return Ok(addr.to_string());
    }
    let network = config
        .finalize
        .deployments_network
        .as_deref()
        .unwrap_or(DEFAULT_DEPLOYMENTS_NETWORK);
    let path = format!("psy-contracts/deployments/{}/deployed-contracts.json", network);
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path))?;
    let deployed: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path))?;
    deployed["core"]["Bridge"]
        .as_str()
        .or_else(|| deployed["contracts"]["Bridge"].as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("Bridge not found in {}", path))
}

fn resolve_state_manager_address(config: &BridgeProposeDaemonConfig) -> anyhow::Result<Address> {
    if let Some(addr) = config.finalize.state_manager.as_deref() {
        return addr
            .parse::<Address>()
            .context("invalid state_manager address in daemon config");
    }
    let network = config
        .finalize
        .deployments_network
        .as_deref()
        .unwrap_or(DEFAULT_DEPLOYMENTS_NETWORK);
    crate::bridge::api_client::resolve_contract_address_from_deployments(network, "StateManager")
}

pub(crate) async fn run_l2_bridge_round_with_l1_provider(
    config: &BridgeProposeDaemonConfig,
    provider: &RpcProvider,
    l1_provider: &impl Provider,
    bridge: Address,
    from_checkpoint: u64,
    to_checkpoint: u64,
    confirmation_lag_checkpoints: u64,
    allow_deposit_appends: bool,
    allow_withdrawal_processing: bool,
    state: &DaemonState,
    mut propose_args: ProposeWithdrawalsArgs,
) -> anyhow::Result<L2RoundResult> {
    propose_args.poll_timeout_secs = 0;
    let deployments_network = config
        .finalize
        .deployments_network
        .as_deref()
        .unwrap_or(DEFAULT_DEPLOYMENTS_NETWORK);

    let proved_deposit_count = u64::from(fetch_proved_deposit_count(l1_provider, bridge).await?);
    let pending_deposit_count = fetch_pending_deposit_count(l1_provider, bridge).await?;
    ensure!(
        u64::from(pending_deposit_count) >= proved_deposit_count,
        "pendingDepositCount is behind provedDepositCount: pending={} proved={}",
        pending_deposit_count,
        proved_deposit_count
    );
    let l2_deposit_next_index = fetch_deposit_tree_next_index(provider, to_checkpoint).await?;
    ensure!(
        l2_deposit_next_index <= u64::from(pending_deposit_count),
        "L2 deposit tree has more deposits than L1 pending count: l2_next_index={} pendingDepositCount={}",
        l2_deposit_next_index,
        pending_deposit_count
    );
    let mut deposit_next_index = u32::try_from(l2_deposit_next_index).context("L2 deposit next_index exceeds u32")?;
    let initially_appended_deposits = l2_deposit_next_index.saturating_sub(proved_deposit_count);
    tracing::info!(
        from_checkpoint,
        to_checkpoint,
        proved_deposit_count,
        pending_deposit_count = pending_deposit_count,
        l2_deposit_next_index,
        initially_appended_deposits,
        "bridge deposit cursor sync"
    );
    if initially_appended_deposits > 0 {
        tracing::info!(
            proved_deposit_count,
            l2_deposit_next_index,
            initially_appended_deposits,
            to_checkpoint,
            "L2 deposit tree is ahead of L1 finalized deposit cursor; will finalize already-appended deposits without re-appending"
        );
    }
    if !allow_deposit_appends && u64::from(pending_deposit_count) > l2_deposit_next_index {
        tracing::info!(
            l2_deposit_next_index,
            pending_deposit_count = pending_deposit_count,
            "deferring L2 deposit append while bridge relayer is catching up"
        );
    }

    let mut to_checkpoint = to_checkpoint;
    let mut submitted_l2_work = false;
    
    let mut claim_withdrawals = Vec::new();
    let mut seen_claim_leaf_hashes = HashSet::new();

    // ═══════════════════════════════════════════════════════════════════
    //  ── L2 Call Planning & Submission Loop ──
    // ═══════════════════════════════════════════════════════════════════

    loop {
        let planning_checkpoint = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
        let deposit_next_index =
            u32::try_from(fetch_deposit_tree_next_index(provider, planning_checkpoint).await?)
                .context("L2 deposit next_index exceeds u32")?;
        let plan = build_l2_call_plan(
            provider,
            l1_provider,
            bridge,
            deployments_network,
            &propose_args,
            from_checkpoint,
            to_checkpoint,
            deposit_next_index,
            pending_deposit_count,
            allow_deposit_appends,
            allow_withdrawal_processing,
        )
        .await?;
        record_claim_withdrawals(
            &plan.withdrawals,
            &mut seen_claim_leaf_hashes,
            &mut claim_withdrawals,
        );

        if plan.is_empty() {
            return finish_l2_round(
                provider,
                to_checkpoint,
                proved_deposit_count,
                pending_deposit_count,
                submitted_l2_work,
                claim_withdrawals,
            )
            .await;
        }

        let landed_checkpoint = submit_l2_call_plan(
            config,
            provider,
            &propose_args,
            from_checkpoint,
            to_checkpoint,
            deposit_next_index,
            pending_deposit_count,
            &plan,
            confirmation_lag_checkpoints,
        )
        .await?;

        submitted_l2_work = true;
        // Advance to_checkpoint to the actual landing checkpoint so
        // downstream operations (e.g. fetch_tree_subroot_and_top_proof)
        // read L2 state /after/ the append took effect.
        to_checkpoint = landed_checkpoint;
    }
}

fn apply_claim_report(
    pending_claim_withdrawals: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    report: &claim_withdrawals::BatchWithdrawalsReport,
) {
    for leaf_hash in &report.resolved_leaf_hashes {
        pending_claim_withdrawals.remove(leaf_hash);
    }
    for (leaf_hash, reason) in &report.failure_reasons {
        tracing::warn!(
            leaf_hash,
            reason,
            "withdrawal claim deferred; will retry next round"
        );
    }
}

fn record_claim_withdrawals(
    withdrawals: &[propose_withdrawals::PendingWithdrawal],
    seen: &mut HashSet<String>,
    claims: &mut Vec<propose_withdrawals::PendingWithdrawal>,
) {
    for withdrawal in withdrawals {
        if seen.insert(withdrawal.leaf_hash.clone()) {
            claims.push(withdrawal.clone());
        }
    }
}

async fn build_l2_call_plan(
    provider: &RpcProvider,
    l1_provider: &impl Provider,
    bridge: Address,
    deployments_network: &str,
    propose_args: &ProposeWithdrawalsArgs,
    from_checkpoint: u64,
    to_checkpoint: u64,
    deposit_next_index: u32,
    pending_deposit_count: u32,
    allow_deposit_appends: bool,
    allow_withdrawal_processing: bool,
) -> anyhow::Result<L2CallPlan> {
    let latest_checkpoint = if allow_withdrawal_processing {
        provider
            .get_coordinator_latest_block_state()
            .await
            .map(|s| s.checkpoint_id)
            .unwrap_or(to_checkpoint)
    } else {
        to_checkpoint
    };
    let effective_pending_deposit_count = if allow_deposit_appends {
        pending_deposit_count
    } else {
        deposit_next_index
    };
    let deposit_range = next_deposit_range(deposit_next_index, effective_pending_deposit_count);
    tracing::info!(
        deposit_next_index,
        deposit_to = deposit_range.map(|(_, to)| to).unwrap_or(deposit_next_index),
        pending_deposit_count,
        effective_pending_deposit_count,
        allow_deposit_appends,
        has_deposit_range = deposit_range.is_some(),
        to_checkpoint,
        "bridge L2 round deposit plan"
    );

    let deposit_batch_calls = build_deposit_append_calls(
        l1_provider, bridge, deployments_network, deposit_range,
    )
    .await?;
    let withdrawal_from_checkpoint = from_checkpoint.max(1);
    let l2_withdrawal_next_index = if allow_withdrawal_processing {
        provider
            .get_withdrawal_tree_next_index(latest_checkpoint, BRIDGE_USER_ID_U64)
            .await?
    } else {
        0
    };
    let withdrawals = if allow_withdrawal_processing {
        propose_withdrawals::fetch_pending_bridge_withdrawals(
            propose_args,
            withdrawal_from_checkpoint,
            to_checkpoint.saturating_add(1),
            l2_withdrawal_next_index,
        )
        .await?
    } else {
        Vec::new()
    };
    let withdrawal_batch_calls = build_withdrawal_batch_calls(&withdrawals);

    let all_batch_calls: Vec<ContractCallArgs> = deposit_batch_calls
        .into_iter()
        .chain(withdrawal_batch_calls)
        .collect();

    tracing::info!(
        l2_withdrawal_next_index,
        append_withdrawals_count = withdrawals.len(),
        raw_batch_calls = all_batch_calls.len(),
        has_withdrawal_appends = !withdrawals.is_empty(),
        allow_withdrawal_processing,
        scan_from_checkpoint = withdrawal_from_checkpoint,
        scan_to_checkpoint = to_checkpoint,
        "bridge L2 round batch plan"
    );

    Ok(L2CallPlan {
        deposit_range,
        withdrawals,
        batch_calls: all_batch_calls,
    })
}

fn next_deposit_range(deposit_next_index: u32, pending_deposit_count: u32) -> Option<(u32, u32)> {
    (deposit_next_index < pending_deposit_count).then_some((deposit_next_index, pending_deposit_count))
}

async fn build_deposit_append_calls(
    l1_provider: &impl Provider,
    bridge: Address,
    deployments_network: &str,
    deposit_range: Option<(u32, u32)>,
) -> anyhow::Result<Vec<ContractCallArgs>> {
    let Some((from_deposit_index, to_deposit_index_exclusive)) = deposit_range else {
        return Ok(Vec::new());
    };
    let count = to_deposit_index_exclusive - from_deposit_index;
    let deposit_calls = fetch_pending_deposit_calls(
        l1_provider,
        bridge,
        deployments_network,
        from_deposit_index,
        to_deposit_index_exclusive,
    )
    .await?;

    tracing::info!(
        from_deposit_index,
        to_deposit_index_exclusive = to_deposit_index_exclusive - 1,
        count,
        "building batch deposit calls for {} deposit(s)",
        count
    );

    Ok(build_deposit_batch_calls(&deposit_calls))
}

async fn finish_l2_round(
    provider: &RpcProvider,
    to_checkpoint: u64,
    proved_deposit_count: u64,
    pending_deposit_count: u32,
    submitted_l2_work: bool,
    
    claim_withdrawals: Vec<propose_withdrawals::PendingWithdrawal>,
) -> anyhow::Result<L2RoundResult> {
    let deposits_consumed = compute_deposits_consumed_for_proof(
        provider,
        to_checkpoint,
        proved_deposit_count,
        pending_deposit_count,
    )
    .await?;

    tracing::info!(
        deposits_consumed,
        to_checkpoint,
        submitted_l2_work,
        claim_withdrawals_count = claim_withdrawals.len(),
        "bridge L2 round has no new L2 calls; returning for prove/finalize"
    );
    Ok(L2RoundResult {
        deposits_consumed,
        to_checkpoint,
        submitted_l2_work,
        claim_withdrawals,
    })
}

async fn submit_l2_call_plan(
    config: &BridgeProposeDaemonConfig,
    provider: &RpcProvider,
    propose_args: &ProposeWithdrawalsArgs,
    from_checkpoint: u64,
    to_checkpoint: u64,
    deposit_next_index: u32,
    pending_deposit_count: u32,
    plan: &L2CallPlan,
    confirmation_lag_checkpoints: u64,
) -> anyhow::Result<u64> {
    let (mut wallet_session, user_pk_hash) = create_wallet_session(config).await?;
    let relayer_user_id = provider
        .get_user_ids_for_public_key(user_pk_hash)
        .await?
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No user id found for relayer public key"))?;
    ensure!(
        relayer_user_id == BRIDGE_USER_ID_U64,
        "relayer wallet user id mismatch: resolved {} but bridge proof/L1 StateManager expect {}; use the private key registered for BRIDGE_USER_ID",
        relayer_user_id,
        BRIDGE_USER_ID_U64
    );
    let checkpoint_before = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
    let batch_count = plan.batch_calls.len();
    let max_conc: usize = 1;

    tracing::info!(
        batch_count,
        max_conc,
        "submitting {} L2 batch(es) with concurrency {}",
        batch_count,
        max_conc,
    );

    let mut last_landed = checkpoint_before;
    let mut futures: FuturesUnordered<
        std::pin::Pin<Box<dyn futures::Future<Output = anyhow::Result<(usize, QHashOut<GoldilocksField>)>> + Send>>,
    > = FuturesUnordered::new();
    let mut submitted = 0usize;

    // Seed the initial wave
    let initial = max_conc.min(batch_count);
    for i in 0..initial {
        let call = plan.batch_calls[i].clone();
        tracing::info!(
            method = call.method_name,
            contract_id = call.contract_id,
            inputs = call.inputs.len(),
            "submitting L2 batch {}",
            call.method_name
        );
        let cfg = config.clone();
        futures.push(Box::pin(async move {
            let (mut session, pk) = create_wallet_session(&cfg).await?;
            let leaf = session.exec_contract_call(pk, ContractCallData::new(vec![call])).await?;
            Ok((i, leaf))
        }));
    }
    submitted = initial;

    // Drain the stream, submitting new batches as slots open up
    while let Some(result) = futures.next().await {
        let (idx, leaf) = result?;

        last_landed = provider
            .wait_for_endcap_inclusion(
                relayer_user_id,
                leaf,
                last_landed,
                Some(REALM_CHECKPOINT_POLL_TIMEOUT_SECS),
                REALM_CHECKPOINT_POLL_INTERVAL_SECS,
            )
            .await
            .with_context(|| format!("L2 batch {} endcap inclusion failed", idx))?;

        tracing::info!(
            batch_index = idx,
            batch_count,
            last_landed,
            "L2 batch call landed"
        );

        if submitted < batch_count {
            let call = plan.batch_calls[submitted].clone();
            tracing::info!(
                method = call.method_name,
                contract_id = call.contract_id,
                inputs = call.inputs.len(),
                "submitting L2 batch {}",
                call.method_name
            );
            let cfg = config.clone();
            futures.push(Box::pin(async move {
                let (mut session, pk) = create_wallet_session(&cfg).await?;
                let leaf = session.exec_contract_call(pk, ContractCallData::new(vec![call])).await?;
                Ok((submitted, leaf))
            }));
            submitted += 1;
        }
    }

    // Wait for confirmation on the LAST checkpoint
    wait_until_checkpoint_confirmed(
        provider,
        last_landed,
        confirmation_lag_checkpoints,
        REALM_CHECKPOINT_POLL_TIMEOUT_SECS,
        REALM_CHECKPOINT_POLL_INTERVAL_SECS,
    )
    .await?;

    Ok(last_landed)
}

async fn wait_until_checkpoint_confirmed(
    provider: &RpcProvider,
    checkpoint_id: u64,
    confirmation_lag_checkpoints: u64,
    timeout_secs: u64,
    poll_interval_secs: u64,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let latest = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
        if latest
            .checked_sub(confirmation_lag_checkpoints)
            .is_some_and(|confirmed_to_checkpoint| confirmed_to_checkpoint >= checkpoint_id)
        {
            tracing::info!(
                checkpoint_id,
                latest_checkpoint = latest,
                confirmation_lag_checkpoints,
                "checkpoint has enough confirmations for bridge event scan"
            );
            return Ok(());
        }

        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for checkpoint {} to reach confirmation lag {}",
                checkpoint_id,
                confirmation_lag_checkpoints
            );
        }

        tracing::debug!(
            checkpoint_id,
            latest_checkpoint = latest,
            confirmation_lag_checkpoints,
            "waiting for checkpoint confirmations before rescanning bridge events"
        );
        tokio::time::sleep(Duration::from_secs(poll_interval_secs)).await;
    }
}

/// Estimate gas for a batch deposit append by estimating on the full
/// multicall3 aggregate3 wrapper instead of individual bridge calls.
/// Individual bridge `batchAppend` calls can revert during estimation
/// because `fromIndex != provedDepositCount` for the second+ call in
/// isolation, but inside multicall3 the sequential execution carries
/// state forward correctly.
async fn estimate_multicall_batch_append_gas(
    provider: &impl Provider,
    multicall3: Address,
    calls: &[Call3],
) -> Vec<u64> {
    if calls.is_empty() {
        return Vec::new();
    }

    // Try estimating on the full aggregate first (this executes calls
    // sequentially, matching real multicall3 behavior).
    let full_aggregate = aggregate3Call {
        calls: calls.to_vec(),
    };
    let full_tx = TransactionRequest::default()
        .to(multicall3)
        .input(Bytes::from(full_aggregate.abi_encode()).into());

    let total_gas = match provider.estimate_gas(full_tx).await {
        Ok(gas) => u64::try_from(gas).unwrap_or(u64::MAX),
        Err(_) => {
            // If the full aggregate cannot be estimated (e.g. too large),
            // use the full multicall budget as the total estimate.
            tracing::warn!(
                n = calls.len(),
                budget = L1_MULTICALL_GAS_BUDGET,
                fallback_per_call = L1_GROTH16_CALL_GAS_FALLBACK,
                "full aggregate gas estimation failed; using budget as total"
            );
            L1_MULTICALL_GAS_BUDGET
        }
    };

    // Divide total gas evenly across calls, capping each at budget.
    let n = calls.len() as u64;
    let per_call = core::cmp::min(total_gas / n, L1_MULTICALL_GAS_BUDGET / n).max(1);
    vec![per_call; calls.len()]
}

/// Chunk deposit batch append calls into multicall3-compatible groups
/// using multicall-level gas estimation (avoiding per-call estimation
/// that reverts with `InvalidBatchRange` for later calls).
async fn chunk_deposit_batch_append_by_gas(
    provider: &impl Provider,
    multicall3: Address,
    calls: Vec<Call3>,
) -> Vec<Vec<Call3>> {
    let gases = estimate_multicall_batch_append_gas(provider, multicall3, &calls).await;

    let budget = L1_MULTICALL_GAS_BUDGET.max(1);
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut current_gas = 0u64;

    for (idx, call) in calls.into_iter().enumerate() {
        let gas = gases.get(idx).copied().unwrap_or(L1_GROTH16_CALL_GAS_FALLBACK).max(1);
        if !current.is_empty() && current_gas.saturating_add(gas) > budget {
            chunks.push(current);
            current = Vec::new();
            current_gas = 0;
        }
        current.push(call);
        current_gas = current_gas.saturating_add(gas);
    }

    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

async fn fetch_proved_deposit_count(provider: &impl Provider, bridge: Address) -> anyhow::Result<u32> {
    let proved = crate::bridge::api_client::eth_call_u256(provider, bridge, provedDepositCountCall {}).await?;
    u32::try_from(proved).context("provedDepositCount exceeds u32")
}

async fn fetch_pending_deposit_count(provider: &impl Provider, bridge: Address) -> anyhow::Result<u32> {
    let pending = crate::bridge::api_client::eth_call_u256(provider, bridge, pendingDepositCountCall {}).await?;
    u32::try_from(pending).context("pendingDepositCount exceeds u32")
}

async fn fetch_pending_deposit_calls(
    provider: &impl Provider,
    bridge: Address,
    deployments_network: &str,
    from_deposit_index: u32,
    to_deposit_index_exclusive: u32,
) -> anyhow::Result<Vec<DepositAppendCall>> {
    #[derive(Deserialize)]
    struct ReceiptLite {
        #[serde(rename = "blockNumber")]
        block_number: u64,
    }
    #[derive(Deserialize)]
    struct DeploymentArtifactLite {
        receipt: ReceiptLite,
    }

    let artifact_path = format!("psy-contracts/deployments/{deployments_network}/Bridge_Proxy.json");
    let artifact_raw = fs::read_to_string(&artifact_path)
        .with_context(|| format!("failed to read {}", artifact_path))?;
    let artifact: DeploymentArtifactLite = serde_json::from_str(&artifact_raw)
        .with_context(|| format!("failed to parse {}", artifact_path))?;

    let records = crate::bridge::deposit_logs::bulk_fetch_deposit_records(
        provider,
        bridge,
        BlockNumberOrTag::Number(artifact.receipt.block_number),
        from_deposit_index,
        to_deposit_index_exclusive,
    )
    .await?;

    let mut ordered = Vec::with_capacity((to_deposit_index_exclusive - from_deposit_index) as usize);
    for index in from_deposit_index..to_deposit_index_exclusive {
        let event = records.get(&index).ok_or_else(|| {
            anyhow::anyhow!("missing DepositRecorded log for index {}", index)
        })?;
        let args = ComputeDepositLeafArgs {
            shield_address: event.shieldAddress,
            token: event.token,
            l2_token_contract_id: event.l2TokenContractId,
            amount: event.amount,
            chain_index: u32::from(event.chainIndex),
            note_secret_hash: event.noteSecretHash,
        };
        let result = compute_deposit_leaf::compute(args);
        let leaf_hex = result.leaf_hex;
        tracing::info!(
            deposit_index = index,
            chain_index = u32::from(event.chainIndex),
            leaf_hex = %leaf_hex,
            "prepared deposit leaf from bulk-fetched logs"
        );
        let leaf_words: [u32; 8] = result
            .append_inputs
            .iter()
            .copied()
            .skip(1)
            .take(8)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid deposit leaf words length for index {}", index))?;
        ordered.push(DepositAppendCall {
            deposit_index: index,
            chain_index: u32::from(event.chainIndex),
            leaf_hex,
            leaf_words,
        });
    }
    Ok(ordered)
}

async fn fetch_deposit_tree_next_index(provider: &RpcProvider, checkpoint_id: u64) -> anyhow::Result<u64> {
    let next_index_slot = provider
        .get_user_contract_state_tree_leaf_hash(
            checkpoint_id,
            BRIDGE_USER_ID_U64,
            DEPOSIT_TREE_CONTRACT_ID,
            CONTRACT_STATE_TREE_HEIGHT,
            2,
        )
        .await?;
    deposit_tree_next_index(next_index_slot)
}

async fn compute_deposits_consumed_for_proof(
    provider: &RpcProvider,
    to_checkpoint: u64,
    proved_deposit_count: u64,
    pending_deposit_count: u32,
) -> anyhow::Result<u64> {
    let l2_deposit_next_index = fetch_deposit_tree_next_index(provider, to_checkpoint).await?;
    ensure!(
        l2_deposit_next_index <= u64::from(pending_deposit_count),
        "L2 deposit tree has more deposits than L1 pending count at prove checkpoint: l2_next_index={} pendingDepositCount={} to_checkpoint={}",
        l2_deposit_next_index,
        pending_deposit_count,
        to_checkpoint
    );
    Ok(l2_deposit_next_index.saturating_sub(proved_deposit_count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_state_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "psy-relayer-daemon-state-{name}-{}-{nanos}.toml",
            std::process::id()
        ))
    }

    #[test]
    fn relayer_window_uses_latest_for_append_only_when_no_confirmed_range_exists() {
        let window = select_relayer_window(63, 65, 3, 32);

        assert_eq!(
            window,
            RelayerWindow {
                to_checkpoint: 65,
                confirmed_to_checkpoint: None,
                is_catchup_batch: false,
            }
        );
        assert!(!window.has_confirmed_range());
    }

    #[test]
    fn relayer_window_caps_append_only_range_by_max_checkpoint_batch() {
        let window = select_relayer_window(63, 200, 300, 32);

        assert_eq!(
            window,
            RelayerWindow {
                to_checkpoint: 94,
                confirmed_to_checkpoint: None,
                is_catchup_batch: false,
            }
        );
        assert!(!window.has_confirmed_range());
    }

    #[test]
    fn relayer_window_append_only_range_is_unbounded_when_max_batch_is_zero() {
        let window = select_relayer_window(63, 200, 300, 0);

        assert_eq!(
            window,
            RelayerWindow {
                to_checkpoint: 200,
                confirmed_to_checkpoint: None,
                is_catchup_batch: false,
            }
        );
        assert!(!window.has_confirmed_range());
    }

    #[test]
    fn relayer_window_uses_confirmed_range_when_available() {
        let window = select_relayer_window(63, 66, 3, 32);

        assert_eq!(
            window,
            RelayerWindow {
                to_checkpoint: 63,
                confirmed_to_checkpoint: Some(63),
                is_catchup_batch: false,
            }
        );
        assert!(window.has_confirmed_range());
    }

    #[test]
    fn relayer_window_uses_full_range_when_window_exceeds_max_batch() {
        // When confirmed_to_checkpoint - from_checkpoint + 1 > max_checkpoint_batch,
        // the full confirmed range is used to trigger multi-chunk aggregation.
        let window = select_relayer_window(10, 80, 3, 8);

        assert_eq!(
            window,
            RelayerWindow {
                to_checkpoint: 77,
                confirmed_to_checkpoint: Some(77),
                is_catchup_batch: false,
            }
        );
    }

    #[test]
    fn reconcile_state_advances_to_l1_finalized_checkpoint() {
        let path = temp_state_path("advance");
        let state = DaemonState {
            last_finalized_checkpoint: 10,
            pending_claim_withdrawals: HashMap::new(),
        };

        let reconciled = reconcile_state_with_l1_finalized_checkpoint(state, &path, 12).unwrap();

        assert_eq!(reconciled.last_finalized_checkpoint, 12);
        assert_eq!(load_state(&path).unwrap().last_finalized_checkpoint, 12);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reconcile_state_caps_to_l1_when_local_is_ahead() {
        let path = temp_state_path("clamp");
        let state = DaemonState {
            last_finalized_checkpoint: 20,
            pending_claim_withdrawals: HashMap::new(),
        };

        let reconciled = reconcile_state_with_l1_finalized_checkpoint(state, &path, 18).unwrap();

        assert_eq!(reconciled.last_finalized_checkpoint, 18);
        let saved = load_state(&path).unwrap();
        assert_eq!(saved.last_finalized_checkpoint, 18);
        let _ = std::fs::remove_file(path);
    }
}
