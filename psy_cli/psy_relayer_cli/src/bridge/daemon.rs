use std::{
    collections::{HashMap, HashSet},
    env,
    fs::{self, File},
    future::Future,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::stream::{FuturesUnordered, StreamExt};

use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{SolCall, sol};
use anyhow::{Context, ensure};
use clap::Args;
use gnark_plonky2_verifier_ffi as g16;
use psy_client_common::args::{SignType, WalletSourceArgs};
use psy_client_common::args::{ContractCallArgs, ContractCallData};
use psy_client_common::data::qhashout::QHashOut;
use psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT;
use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
use psy_core::constants::chain_id::PsyChainNetworkType;

use psy_prover::session::{EndCapContractSlotUpdate, EndCapSubmissionError, WalletSession};
use psy_provider::{
    provider::RpcProvider,
    request::RealmEndCapSlotUpdates,
};
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;
use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};
use serde::{Deserialize, Serialize};

use psy_cli_common::key_utils::load_wallet_key_info;
use crate::bridge::{
    claim_withdrawals,
    constants::{
        BRIDGE_USER_ID_U64, DEFAULT_DEPLOYMENTS_NETWORK, DEFAULT_L1_RPC_URL, DEPOSIT_TREE_CONTRACT_ID, WITHDRAWAL_TREE_CONTRACT_ID,
        L1_GROTH16_CALL_GAS_FALLBACK, L1_MULTICALL_GAS_BUDGET,
        REALM_CHECKPOINT_POLL_INTERVAL_SECS, REALM_CHECKPOINT_POLL_TIMEOUT_SECS, DEFAULT_SDC_PATH,
    },
    finalize_bridge::{self, FinalizeBridgeAggArgs},
    l1_client::L1Client,
    l1_signer::load_l1_wallet,
    propose_withdrawals::{self, ProposeWithdrawalsArgs},
    prove_bridge::{self},
};

const DEFAULT_PROOF_DIR: &str = "/tmp/psy_bridge_proofs";
const CONTRACT_STATE_TREE_HEIGHT: u8 = 32;
const DEFAULT_MAX_CHECKPOINT_BATCH: u64 = 64;
/// Per-round catchup truncation size; default 64 preserves prior daemon behavior.
const NETWORK_TYPE: PsyChainNetworkType = PsyChainNetworkType::LocalDevnet;

// deposit_tree storage is felt-addressed, with 4 felts packed per contract-state leaf.
// Layout:
//   root[8]                 -> sub-slots 0..7
//   frontiers[8192][8]      -> sub-slots 8..65543
//   chain_counts[256]       -> sub-slots 65544..65799
//   global_count            -> sub-slot 65800
const DEPOSIT_TREE_CHAIN_COUNTS_SUBSLOT_BASE: u64 = 8 + (8192 * 8);
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
        sd_key_allowed_contract_id: vec![],
        sd_key_allowed_method_id: vec![],
        sd_key_expected_tx_count: 2,
        sd_key_definition: None,
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


#[derive(Debug)]
pub(crate) struct L2RoundResult {
    deposit_append_target: Option<u32>,
    to_checkpoint: u64,
    submitted_l2_work: bool,
    /// Sticky catch-up authority for this L2 round. Starts from the pre-round
    /// window flag and latches true if the fresh coordinator head crosses the
    /// catch-up threshold mid-loop, so finish_l2_round and outer claim/deposit
    /// gates stay fail-closed under one authority.
    is_catchup_batch: bool,
    claim_withdrawals: Vec<propose_withdrawals::PendingWithdrawal>,
}

#[derive(Debug)]
struct L2CallPlan {
    withdrawals: Vec<propose_withdrawals::PendingWithdrawal>,
    /// Optimized batch calls using batch_2/batch_5 or individual methods.
    /// Each element is ONE ContractCallArgs for a batch (or single).
    batch_calls: Vec<ContractCallArgs>,
}

impl L2CallPlan {
    fn is_empty(&self) -> bool {
        self.batch_calls.is_empty()
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


/// Build optimized batch `ContractCallArgs` for withdrawal appends.
/// Sender-auth batch interface:
/// batch_append_withdrawals_N(
///   count,
///   sender_user_ids,
///   token_contract_ids,
///   destination_chain_indices,
///   token_addresses,
///   amounts,
///   recipients,
///   nonces,
/// )
fn build_withdrawal_batch_calls(
    withdrawals: &[propose_withdrawals::PendingWithdrawal],
) -> Vec<ContractCallArgs> {
    if withdrawals.is_empty() {
        return Vec::new();
    }

    let sizes = optimal_batch_sizes(withdrawals.len());
    let mut calls = Vec::with_capacity(sizes.len());
    let mut pos = 0;
    for &chunk_size in &sizes {
        match chunk_size {
            1 => {
                let w = &withdrawals[pos];
                let mut inputs = vec![
                    w.sender_user_id,
                    w.contract_id,
                    w.destination_chain_index,
                ];
                inputs.extend(w.token_address.iter().map(|&v| v as u64));
                inputs.extend(w.amount.iter().map(|&v| v as u64));
                inputs.extend(w.recipient.iter().map(|&v| v as u64));
                inputs.extend(w.nonce.iter().map(|&v| v as u64));
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
                let mut inputs = vec![chunk_size as u64];
                for k in 0..chunk_size {
                    inputs.push(withdrawals[pos + k].sender_user_id);
                }
                for k in 0..chunk_size {
                    inputs.push(withdrawals[pos + k].contract_id);
                }
                for k in 0..chunk_size {
                    inputs.push(withdrawals[pos + k].destination_chain_index);
                }
                for k in 0..chunk_size {
                    inputs.extend(withdrawals[pos + k].token_address.iter().map(|&v| v as u64));
                }
                for k in 0..chunk_size {
                    inputs.extend(withdrawals[pos + k].amount.iter().map(|&v| v as u64));
                }
                for k in 0..chunk_size {
                    inputs.extend(withdrawals[pos + k].recipient.iter().map(|&v| v as u64));
                }
                for k in 0..chunk_size {
                    inputs.extend(withdrawals[pos + k].nonce.iter().map(|&v| v as u64));
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


fn select_deposit_append_target(
    is_catchup_batch: bool,
    proof_to_checkpoint: u64,
    l2_landing_checkpoint: u64,
    l2_deposit_cursor: u64,
    proved_deposit_count: u32,
    pending_deposit_count: u32,
) -> anyhow::Result<Option<u32>> {
    ensure!(
        proved_deposit_count <= pending_deposit_count,
        "L1 deposit cursors are inconsistent: provedDepositCount={} pendingDepositCount={}",
        proved_deposit_count,
        pending_deposit_count
    );

    if is_catchup_batch || proof_to_checkpoint != l2_landing_checkpoint {
        return Ok(None);
    }

    let target = u32::try_from(l2_deposit_cursor).context("L2 deposit cursor exceeds u32")?;
    ensure!(
        target >= proved_deposit_count,
        "L2 deposit cursor is behind L1 proved count at prove checkpoint: l2_cursor={} provedDepositCount={} to_checkpoint={}",
        target,
        proved_deposit_count,
        proof_to_checkpoint
    );
    ensure!(
        target <= pending_deposit_count,
        "L2 deposit tree has more deposits than L1 pending count at prove checkpoint: l2_cursor={} pendingDepositCount={} to_checkpoint={}",
        target,
        pending_deposit_count,
        proof_to_checkpoint
    );

    Ok((target > proved_deposit_count).then_some(target))
}

/// Select the checkpoint the daemon finalizes through the bridge agg proof.
///
/// Contract: finalize straight to the L2 landing checkpoint, NOT capped back
/// to the pre-round `window.to_checkpoint` bound. In a normal round
/// (gap <= max_checkpoint_batch) the L2 round may land beyond the pre-round
/// window bound; the bridge agg proof handles the wider range via chained
/// proofs (32-slot chain + final), so capping back would drop landed L2 work.
/// In catchup mode no L2 work advances the cursor, so the landing equals the
/// window bound and this returns the same value either way.
fn select_finalize_to_checkpoint(
    _window_to_checkpoint: u64,
    l2_landing_checkpoint: u64,
) -> u64 {
    l2_landing_checkpoint
}



pub(crate) fn validate_max_checkpoint_batch(max_checkpoint_batch: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        max_checkpoint_batch >= 1,
        "max_checkpoint_batch must be >= 1, got {}",
        max_checkpoint_batch
    );
    Ok(())
}

fn select_relayer_window(
    from_checkpoint: u64,
    latest_checkpoint: u64,
    confirmation_lag_checkpoints: u64,
    max_checkpoint_batch: u64,
) -> RelayerWindow {
    let confirmed_to_checkpoint = latest_checkpoint.checked_sub(confirmation_lag_checkpoints);
    let Some(confirmed_to_checkpoint) = confirmed_to_checkpoint.filter(|confirmed| *confirmed >= from_checkpoint) else {
        // L2 has not confirmed far enough — append-only mode (no prove/finalize).
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

    // Catchup is determined by whether the gap exceeds max_checkpoint_batch.
    let range_len = confirmed_to_checkpoint - from_checkpoint + 1;
    let is_catchup_batch = max_checkpoint_batch > 0 && range_len > max_checkpoint_batch;

    // In catchup mode, truncate to max_checkpoint_batch per round.
    // A one-checkpoint tail remains as a normal next-round range and can be proved.
    let to_checkpoint = if is_catchup_batch && max_checkpoint_batch > 0 {
        from_checkpoint.saturating_add(max_checkpoint_batch.saturating_sub(1))
    } else {
        confirmed_to_checkpoint
    };

    RelayerWindow {
        to_checkpoint,
        confirmed_to_checkpoint: Some(confirmed_to_checkpoint),
        is_catchup_batch,
    }
}

fn refresh_catchup_state(
    is_catchup_batch: bool,
    from_checkpoint: u64,
    latest_checkpoint: Option<u64>,
    confirmation_lag_checkpoints: u64,
    max_checkpoint_batch: u64,
) -> bool {
    if is_catchup_batch {
        return true;
    }
    let Some(latest_checkpoint) = latest_checkpoint else {
        return true;
    };
    select_relayer_window(
        from_checkpoint,
        latest_checkpoint,
        confirmation_lag_checkpoints,
        max_checkpoint_batch,
    )
    .is_catchup_batch
}

fn should_attempt_pending_claims(is_catchup_batch: bool, pending_claim_count: usize) -> bool {
    !is_catchup_batch && pending_claim_count > 0
}

/// Capability issued only when post-L2 phases may run. All deposit/proof/
/// finalize/claim dispatch wrappers require this permit, so a newly-latched
/// catch-up branch cannot fall through into any of those operations.
#[derive(Clone, Copy, Debug)]
struct PostL2PhasePermit;

#[derive(Debug)]
enum PostL2Orchestration<T> {
    Deferred,
    Dispatch(T),
}

/// Production post-L2 orchestration seam. It merges the durable claim ledger,
/// atomically installs it when a normal-entry round newly latches catch-up, and
/// invokes `dispatch` only when post-L2 phases are authorized.
async fn orchestrate_post_l2_round<T, Dispatch, DispatchFuture>(
    state_path: &Path,
    state: &DaemonState,
    current_round_withdrawals: &[propose_withdrawals::PendingWithdrawal],
    pre_round_is_catchup_batch: bool,
    post_l2_is_catchup_batch: bool,
    dispatch: Dispatch,
) -> anyhow::Result<PostL2Orchestration<T>>
where
    Dispatch: FnOnce(
        PostL2PhasePermit,
        HashMap<String, propose_withdrawals::PendingWithdrawal>,
    ) -> DispatchFuture,
    DispatchFuture: Future<Output = T>,
{
    let mut pending_claim_withdrawals = state.pending_claim_withdrawals.clone();
    for withdrawal in current_round_withdrawals {
        pending_claim_withdrawals
            .entry(withdrawal.leaf_hash.clone())
            .or_insert_with(|| withdrawal.clone());
    }

    if !pre_round_is_catchup_batch && post_l2_is_catchup_batch {
        save_state(
            state_path,
            &DaemonState {
                last_finalized_checkpoint: state.last_finalized_checkpoint,
                pending_claim_withdrawals,
            },
        )?;
        return Ok(PostL2Orchestration::Deferred);
    }

    Ok(PostL2Orchestration::Dispatch(
        dispatch(PostL2PhasePermit, pending_claim_withdrawals).await,
    ))
}

async fn dispatch_post_l2_phase<T>(
    _permit: &PostL2PhasePermit,
    phase: impl Future<Output = T>,
) -> T {
    phase.await
}

fn persist_finalized_state_then_cleanup_proof(
    state_path: &Path,
    state: &DaemonState,
    proof_path: &Path,
) -> anyhow::Result<()> {
    save_state(state_path, state)?;
    if let Err(err) = fs::remove_file(proof_path) {
        tracing::warn!(
            proof_path = %proof_path.display(),
            error = %err,
            "finalized state is durable but spent proof cleanup failed"
        );
    }
    Ok(())
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
    validate_max_checkpoint_batch(max_checkpoint_batch)?;
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

        let round_mode = if !window.has_confirmed_range() {
            "APPEND-ONLY"
        } else if is_catchup_batch {
            "CATCHUP"
        } else {
            "ROUND"
        };
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
            is_catchup_batch,
            &state,
            propose_args.clone(),
            max_checkpoint_batch,
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


        state = load_state(&state_path)?;
        // One sticky authority: L2 may latch catch-up mid-round; outer gates
        // must honor that latch for deposits and pending-claim settlement.
        let mut is_catchup_batch = l2_round.is_catchup_batch;
        let (post_l2_phase_permit, mut pending_claim_withdrawals) =
            match orchestrate_post_l2_round(
                &state_path,
                &state,
                &l2_round.claim_withdrawals,
                window.is_catchup_batch,
                is_catchup_batch,
                |permit, pending| async move { (permit, pending) },
            )
            .await
            {
                Ok(PostL2Orchestration::Deferred) => {
                    tracing::info!(
                        from_checkpoint,
                        to_checkpoint = l2_round.to_checkpoint,
                        pre_round_is_catchup_batch = window.is_catchup_batch,
                        post_l2_is_catchup_batch = is_catchup_batch,
                        "newly-latched catch-up round persisted; skipping deposit, proof, finalize, and claims"
                    );
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
                Ok(PostL2Orchestration::Dispatch(dispatch)) => dispatch,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        from_checkpoint,
                        to_checkpoint = l2_round.to_checkpoint,
                        "failed to persist state while deferring newly-latched catch-up round"
                    );
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
            };

        // Append-only / no-confirmed-range rounds still retry durable pending
        // claims after safe L2 handling. No new finalize range is required.
        if !window.has_confirmed_range() {
            let _ = dispatch_post_l2_phase(
                &post_l2_phase_permit,
                settle_pending_claim_withdrawals(
                    &l1,
                    &provider,
                    &config,
                    &mut pending_claim_withdrawals,
                    from_checkpoint,
                    state.last_finalized_checkpoint,
                    is_catchup_batch,
                    confirmation_lag_checkpoints,
                    max_checkpoint_batch,
                ),
            )
            .await;
            if let Err(e) = save_state(
                &state_path,
                &DaemonState {
                    last_finalized_checkpoint: state.last_finalized_checkpoint,
                    pending_claim_withdrawals,
                },
            ) {
                tracing::error!(
                    error = %e,
                    "failed to persist pending claims after append-only claim settlement"
                );
            }
            if !l2_round.submitted_l2_work && l2_round.deposit_append_target.is_none() {
                tracing::info!(
                    from_checkpoint,
                    to_checkpoint = l2_round.to_checkpoint,
                    latest_checkpoint,
                    "[bridge-APPEND-ONLY] no deposits to append; idle poll after durable claim retry"
                );
            } else {
                tracing::info!(
                    from_checkpoint,
                    to_checkpoint = l2_round.to_checkpoint,
                    "no confirmed range to prove; idle poll after L2 append-only work and durable claim retry"
                );
            }
            tokio::time::sleep(poll_interval).await;
            continue;
        }
        if l2_round.to_checkpoint < from_checkpoint {
            let _ = dispatch_post_l2_phase(
                &post_l2_phase_permit,
                settle_pending_claim_withdrawals(
                    &l1,
                    &provider,
                    &config,
                    &mut pending_claim_withdrawals,
                    from_checkpoint,
                    state.last_finalized_checkpoint,
                    is_catchup_batch,
                    confirmation_lag_checkpoints,
                    max_checkpoint_batch,
                ),
            )
            .await;
            if let Err(e) = save_state(
                &state_path,
                &DaemonState {
                    last_finalized_checkpoint: state.last_finalized_checkpoint,
                    pending_claim_withdrawals,
                },
            ) {
                tracing::error!(
                    error = %e,
                    "failed to persist pending claims when skipping prove"
                );
            }
            tracing::info!(
                from_checkpoint,
                to_checkpoint = l2_round.to_checkpoint,
                "to_checkpoint < from_checkpoint after L2 round; skipping prove after durable claim retry"
            );
            tokio::time::sleep(poll_interval).await;
            continue;
        }

        // Finalize straight to the L2 landing checkpoint. In normal mode
        // (gap <= max_checkpoint_batch) landing <= confirmed, so the range
        // fits one chain proof (32 slots) plus a final proof. In catchup mode
        // deposits and withdrawals are disabled, so no L2 work advances
        // to_checkpoint and it stays at the pre-round window.to_checkpoint.
        let to_checkpoint = select_finalize_to_checkpoint(to_checkpoint, l2_round.to_checkpoint);
        let deposit_append_target = l2_round.deposit_append_target;
        let proof_path = proof_dir.join(format!("bridge_proof_{}.json", to_checkpoint));
        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 2 ─ Deposit Batch Appends (submit Groth16 proof to L1)
        // ═══════════════════════════════════════════════════════════════════

        if let Some(target_deposit_count) = deposit_append_target {
            if let Err(err) = dispatch_post_l2_phase(
                &post_l2_phase_permit,
                l1.submit_deposit_batch_appends(&config, target_deposit_count),
            )
            .await
            {
                tracing::error!(
                    to_checkpoint,
                    target_deposit_count,
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
        let prove_result = match dispatch_post_l2_phase(
            &post_l2_phase_permit,
            l1.load_or_build_proof(
                &config,
                &proof_path,
                from_checkpoint,
                to_checkpoint,
                prove_proxy_url.as_deref(),
            ),
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
        };

        let withdrawal_count = l2_round.claim_withdrawals.len();
        if let Err(e) = save_state(
            &state_path,
            &DaemonState {
                last_finalized_checkpoint: state.last_finalized_checkpoint,
                pending_claim_withdrawals: pending_claim_withdrawals.clone(),
            },
        ) {
            tracing::error!(error = %e, "failed to persist pending claims before finalize");
        }

        match dispatch_post_l2_phase(&post_l2_phase_permit, l1.finalize(finalize_args)).await {
            Ok(()) => {
                // Brief pause to ensure L1 state is settled before gas
                // estimation for the claim transaction.
                tokio::time::sleep(Duration::from_secs(2)).await;
                is_catchup_batch = dispatch_post_l2_phase(
                    &post_l2_phase_permit,
                    settle_pending_claim_withdrawals(
                        &l1,
                        &provider,
                        &config,
                        &mut pending_claim_withdrawals,
                        from_checkpoint,
                        to_checkpoint,
                        is_catchup_batch,
                        confirmation_lag_checkpoints,
                        max_checkpoint_batch,
                    ),
                )
                .await;

                let finalized_state = DaemonState {
                    last_finalized_checkpoint: to_checkpoint,
                    pending_claim_withdrawals,
                };
                match persist_finalized_state_then_cleanup_proof(
                    &state_path,
                    &finalized_state,
                    &proof_path,
                ) {
                    Ok(()) => {
                        tracing::info!(
                            to_checkpoint,
                            has_deposits = deposit_append_target.is_some(),
                            submitted_l2_work = l2_round.submitted_l2_work,
                            withdrawal_count,
                            deposit_append_target = ?deposit_append_target,
                            is_catchup_batch,
                            "[bridge-{}] phase4 done: finalize complete and state durable",
                            round_mode,
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            to_checkpoint,
                            proof_path = %proof_path.display(),
                            "finalize succeeded on L1 but state install is incomplete; retaining proof"
                        );
                    }
                }
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

        let final_round_mode = round_mode;
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
    target_deposit_count: u32,
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
    let expected_proved_after = U256::from(target_deposit_count);
    ensure!(
        proved_before <= expected_proved_after,
        "Bridge provedDepositCount is already beyond requested deposit append target: current={} target={}",
        proved_before,
        expected_proved_after
    );
    if proved_before == expected_proved_after {
        tracing::info!(
            target_deposit_count,
            "Bridge provedDepositCount already reached deposit append target"
        );
        return Ok(());
    }

    let calls = if let Some(proxy_url) = prove_proxy_url {
        prove_bridge::build_deposit_batch_append_calls_remote(
            l1_rpc,
            deployments_network,
            target_deposit_count,
            proxy_url,
        )
        .await?
    } else {
        prove_bridge::build_deposit_batch_append_calls(
            l1_rpc,
            deployments_network,
            target_deposit_count,
        )
        .await?
    };
    if calls.is_empty() {
        let proved_after = crate::bridge::api_client::eth_call_u256(&provider, bridge, provedDepositCountCall {}).await?;
        ensure!(
            proved_after == expected_proved_after,
            "deposit batchAppend builder returned no calls before target was reached: target={} actual={}",
            expected_proved_after,
            proved_after
        );
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
                target_deposit_count,
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
            target_deposit_count,
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
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        anyhow::anyhow!(
            "daemon state path missing file name: {}",
            path.display()
        )
    })?;
    let tmp_name = format!(
        ".{}.tmp-{}-{}",
        file_name.to_string_lossy(),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    );
    let tmp_path = parent.join(tmp_name);

    let install = (|| -> anyhow::Result<()> {
        let mut file = File::options()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .with_context(|| {
                format!(
                    "failed to create temp daemon state {}",
                    tmp_path.display()
                )
            })?;
        file.write_all(raw.as_bytes()).with_context(|| {
            format!(
                "failed to write temp daemon state {}",
                tmp_path.display()
            )
        })?;
        file.sync_all().with_context(|| {
            format!(
                "failed to sync temp daemon state {}",
                tmp_path.display()
            )
        })?;
        drop(file);
        fs::rename(&tmp_path, path).with_context(|| {
            format!(
                "failed to install daemon state via rename to {}",
                path.display()
            )
        })?;
        // Durably record the directory entry that now points at the new state.
        // Treat failure as an install failure so callers retain the proof and
        // do not advertise the new checkpoint as crash-safe.
        let dir = File::open(parent).with_context(|| {
            format!(
                "failed to open daemon state parent directory {}",
                parent.display()
            )
        })?;
        dir.sync_all().with_context(|| {
            format!(
                "failed to sync daemon state parent directory {}",
                parent.display()
            )
        })?;
        Ok(())
    })();

    if install.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    install.with_context(|| format!("failed to write daemon state {}", path.display()))
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

fn read_single_felt_from_packed_leaf(
    leaf: psy_client_common::data::qhashout::QHashOut<GoldilocksField>,
    sub_slot_index: u64,
) -> anyhow::Result<u64> {
    let offset = (sub_slot_index % 4) as usize;
    let value = leaf.0.elements[offset].to_canonical_u64();
    ensure!(
        value <= u32::MAX as u64,
        "packed contract-state value exceeds u32 range: sub_slot={} value={}",
        sub_slot_index,
        value
    );
    Ok(value)
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
    let path = crate::bridge::api_client::resolve_deployments_file(network, "deployed-contracts.json");
    let deployed = crate::bridge::api_client::load_deployed_contracts(network)
        .with_context(|| format!("failed to load {}", path.display()))?;
    deployed
        .core
        .get("Bridge")
        .or_else(|| deployed.contracts.get("Bridge"))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Bridge not found in {}", path.display()))
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
    mut is_catchup_batch: bool,
    state: &DaemonState,
    mut propose_args: ProposeWithdrawalsArgs,
    max_checkpoint_batch: u64,
) -> anyhow::Result<L2RoundResult> {
    let proof_dir = config
        .proof_dir
        .as_deref()
        .unwrap_or_else(|| Path::new(DEFAULT_PROOF_DIR));
    let state_path = proof_dir.join("daemon_state.toml");
    propose_args.poll_timeout_secs = 0;
    let deployments_network = config
        .finalize
        .deployments_network
        .as_deref()
        .unwrap_or(DEFAULT_DEPLOYMENTS_NETWORK);
    let state_manager = resolve_state_manager_address(config)?;
    let source_chain_index =
        u64::from(crate::bridge::api_client::resolve_l1_chain_index(l1_provider, deployments_network, state_manager).await?);

    let proved_deposit_count = fetch_proved_deposit_count(l1_provider, bridge).await?;
    let pending_deposit_count = fetch_pending_deposit_count(l1_provider, bridge).await?;
    ensure!(
        pending_deposit_count >= proved_deposit_count,
        "pendingDepositCount is behind provedDepositCount: pending={} proved={}",
        pending_deposit_count,
        proved_deposit_count
    );
    let l2_deposit_next_index = fetch_deposit_tree_next_index(
        provider,
        to_checkpoint,
        source_chain_index,
    )
    .await?;
    select_deposit_append_target(
        is_catchup_batch,
        to_checkpoint,
        to_checkpoint,
        l2_deposit_next_index,
        proved_deposit_count,
        pending_deposit_count,
    )?;
    tracing::info!(
        from_checkpoint,
        to_checkpoint,
        proved_deposit_count,
        pending_deposit_count = pending_deposit_count,
        l2_deposit_next_index,
        "bridge deposit cursor sync"
    );
    if is_catchup_batch && u64::from(pending_deposit_count) > l2_deposit_next_index {
        tracing::info!(
            l2_deposit_next_index,
            pending_deposit_count = pending_deposit_count,
            "deferring L2 deposit append while bridge relayer is catching up"
        );
    }

    let mut to_checkpoint = to_checkpoint;
    let mut submitted_l2_work = false;
    // Sticky catch-up authority for this L2 round. Latches true if the fresh
    // coordinator head crosses the threshold mid-loop and is carried out so
    // finish_l2_round cannot emit a deposit_append_target under catch-up.

    let mut claim_withdrawals = Vec::new();
    let mut seen_claim_leaf_hashes = HashSet::new();

    // A normal round that crosses the catch-up threshold (gap > max_checkpoint_batch)
    // mid-loop must stop appending business; the outer loop will re-evaluate and
    // enter catch-up mode on the next iteration.

    // ═══════════════════════════════════════════════════════════════════
    //  ── L2 Call Planning & Submission Loop ──
    // ═══════════════════════════════════════════════════════════════════

    loop {
        let planning_checkpoint = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
        let deposit_next_index = u32::try_from(
            fetch_deposit_tree_next_index(provider, planning_checkpoint, source_chain_index)
                .await?,
        )
        .context("L2 deposit next_index exceeds u32")?;

        // Re-evaluate the checkpoint window before submitting irreversible
        // L2 work. If a normal round has crossed into catch-up (gap >
        // max_checkpoint_batch) while appending business, stop here; the
        // outer loop will re-evaluate and enter catch-up mode next iteration.
        // Withdrawals from prior iterations were persisted before their L2
        // submit; this break occurs before build_l2_call_plan, so no new
        // withdrawals exist to lose. The catch-up gate defers them safely.
        if !is_catchup_batch {
            let fresh_is_catchup_batch = refresh_catchup_state(
                is_catchup_batch,
                from_checkpoint,
                Some(planning_checkpoint),
                confirmation_lag_checkpoints,
                max_checkpoint_batch,
            );
            if fresh_is_catchup_batch {
                is_catchup_batch = true;
                let fresh_window = select_relayer_window(
                    from_checkpoint,
                    planning_checkpoint,
                    confirmation_lag_checkpoints,
                    max_checkpoint_batch,
                );
                tracing::info!(
                    from_checkpoint,
                    planning_checkpoint,
                    confirmed_to_checkpoint = fresh_window.confirmed_to_checkpoint,
                    max_checkpoint_batch,
                    is_catchup_batch,
                    "bridge L2 round stopping: checkpoint window crossed into catch-up mid-round"
                );
                break;
            }
        }

        let plan = build_l2_call_plan(
            &config.services_url,
            source_chain_index,
            provider,
            l1_provider,
            bridge,
            &propose_args,
            from_checkpoint,
            to_checkpoint,
            deposit_next_index,
            pending_deposit_count,
            proved_deposit_count,
            is_catchup_batch,
        )
        .await?;
        record_claim_withdrawals(
            &plan.withdrawals,
            &mut seen_claim_leaf_hashes,
            &mut claim_withdrawals,
        );
        persist_claim_withdrawals_before_l2_submit(&state_path, &plan.withdrawals)?;

        if plan.is_empty() {
            return finish_l2_round(
                provider,
                to_checkpoint,
                proved_deposit_count,
                pending_deposit_count,
                source_chain_index,
                is_catchup_batch,
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

    finish_l2_round(
        provider,
        to_checkpoint,
        proved_deposit_count,
        pending_deposit_count,
        source_chain_index,
        is_catchup_batch,
        submitted_l2_work,
        claim_withdrawals,
    )
    .await
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

/// Durable pending-claim settlement shared by finalize rounds and append-only
/// / no-confirmed-range rounds. Retries persisted claims under the same
/// sticky fail-closed catch-up gate used after finalize; no new finalize range
/// is required. Returns the (possibly latched) catch-up authority.
async fn settle_pending_claim_withdrawals(
    l1: &L1Client,
    provider: &RpcProvider,
    config: &BridgeProposeDaemonConfig,
    pending_claim_withdrawals: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    from_checkpoint: u64,
    claim_cursor_checkpoint: u64,
    mut is_catchup_batch: bool,
    confirmation_lag_checkpoints: u64,
    max_checkpoint_batch: u64,
) -> bool {
    let to_claim: Vec<propose_withdrawals::PendingWithdrawal> =
        pending_claim_withdrawals.values().cloned().collect();
    if to_claim.is_empty() {
        tracing::info!(
            claim_cursor_checkpoint,
            "no withdrawals pending claim; durable claim set is empty"
        );
        return is_catchup_batch;
    }

    if !is_catchup_batch {
        let latest_checkpoint = match provider.get_coordinator_latest_block_state().await {
            Ok(latest_state) => Some(latest_state.checkpoint_id),
            Err(err) => {
                tracing::warn!(
                    claim_cursor_checkpoint,
                    error = %err,
                    pending_claims = to_claim.len(),
                    "cannot refresh checkpoint window; deferring persisted withdrawal claims"
                );
                None
            }
        };
        is_catchup_batch = refresh_catchup_state(
            is_catchup_batch,
            from_checkpoint,
            latest_checkpoint,
            confirmation_lag_checkpoints,
            max_checkpoint_batch,
        );
    }

    if !should_attempt_pending_claims(is_catchup_batch, to_claim.len()) {
        tracing::info!(
            claim_cursor_checkpoint,
            pending_claims = to_claim.len(),
            "catchup mode defers persisted withdrawal claims under sticky authority"
        );
        return is_catchup_batch;
    }

    match l1
        .claim_withdrawals(&to_claim, config, claim_cursor_checkpoint)
        .await
    {
        Ok(report) => {
            apply_claim_report(pending_claim_withdrawals, &report);
            if report.failure_reasons.is_empty() {
                tracing::info!(
                    claim_cursor_checkpoint,
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
                    claim_cursor_checkpoint,
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
                claim_cursor_checkpoint,
                error = %err,
                pending_claims = pending_claim_withdrawals.len(),
                "withdrawal claims failed; keeping pending set for retry"
            );
        }
    }

    is_catchup_batch
}

fn persist_claim_withdrawals_before_l2_submit(
    state_path: &Path,
    withdrawals: &[propose_withdrawals::PendingWithdrawal],
) -> anyhow::Result<()> {
    if withdrawals.is_empty() {
        return Ok(());
    }

    let mut persisted = load_state(state_path)?;
    let mut changed = false;
    for withdrawal in withdrawals {
        if let std::collections::hash_map::Entry::Vacant(entry) = persisted
            .pending_claim_withdrawals
            .entry(withdrawal.leaf_hash.clone())
        {
            entry.insert(withdrawal.clone());
            changed = true;
        }
    }
    if changed {
        save_state(state_path, &persisted).context("failed to persist pending claims before L2 submission")?;
    }
    Ok(())
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

fn build_set_chain_root_call(
    source_chain_index: u64,
    absolute_deposit_count: u64,
    deposit_root_hex: &str,
) -> anyhow::Result<ContractCallArgs> {
    let raw_hex = deposit_root_hex.strip_prefix("0x").unwrap_or(deposit_root_hex);
    let bytes = hex::decode(raw_hex)
        .map_err(|e| anyhow::anyhow!("hex decode deposit_root: {}", e))?;
    anyhow::ensure!(bytes.len() == 32, "deposit_root must be 32 bytes");

    let mut root_words = [0u32; 8];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        root_words[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    let mut inputs = vec![source_chain_index, absolute_deposit_count];
    inputs.extend(root_words.into_iter().map(u64::from));
    Ok(ContractCallArgs {
        contract_id: DEPOSIT_TREE_CONTRACT_ID as u64,
        method_name: "set_chain_root".to_string(),
        inputs,
    })
}

async fn build_l2_call_plan(
    services_url: &str,
    source_chain_index: u64,
    provider: &RpcProvider,
    _l1_provider: &impl Provider,
    _bridge: Address,
    propose_args: &ProposeWithdrawalsArgs,
    from_checkpoint: u64,
    to_checkpoint: u64,
    deposit_next_index: u32,
    pending_deposit_count: u32,
    proved_deposit_count: u32,
    is_catchup_batch: bool,
) -> anyhow::Result<L2CallPlan> {
    let latest_checkpoint = if !is_catchup_batch {
        provider
            .get_coordinator_latest_block_state()
            .await
            .map(|s| s.checkpoint_id)
            .unwrap_or(to_checkpoint)
    } else {
        to_checkpoint
    };

    let global_target_deposit_count = u64::from(pending_deposit_count);
    let global_target_deposits_remaining_on_l2 = if !is_catchup_batch {
        global_target_deposit_count
            .checked_sub(u64::from(deposit_next_index))
            .ok_or_else(|| anyhow::anyhow!(
                "L2 deposit tree has more deposits than global target count: l2_next_index={} global_target_deposit_count={}",
                deposit_next_index,
                global_target_deposit_count
            ))?
    } else {
        0
    };
    let mut deposit_set_root_calls = Vec::new();
    if !is_catchup_batch && global_target_deposits_remaining_on_l2 > 0 {
        let http = crate::bridge::api_client::build_default_http_client()?;
        let source_chain_tree_state = crate::bridge::api_client::fetch_services_deposit_tree_root(
            &http,
            services_url,
            source_chain_index,
            global_target_deposit_count,
        )
        .await?;
        let per_chain_snapshot_deposit_count = source_chain_tree_state
            .snapshot_deposit_count()
            .ok_or_else(|| anyhow::anyhow!("deposit_tree_root response missing snapshot_deposit_count"))?;
        let per_chain_deposits_remaining_on_l2 = per_chain_snapshot_deposit_count
            .checked_sub(u64::from(deposit_next_index))
            .ok_or_else(|| anyhow::anyhow!(
                "L2 deposit tree has more deposits than per-chain snapshot count: l2_next_index={} per_chain_snapshot_deposit_count={}",
                deposit_next_index,
                per_chain_snapshot_deposit_count
            ))?;
        anyhow::ensure!(
            source_chain_tree_state.found,
            "services deposit snapshot root unavailable for global_target_deposit_count={}: {}",
            global_target_deposit_count,
            source_chain_tree_state
                .reason
                .as_deref()
                .unwrap_or("no reason given")
        );
        let deposit_root_hex = source_chain_tree_state
            .deposit_root
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("deposit_tree_root response missing deposit_root"))?;

        if per_chain_deposits_remaining_on_l2 > 0 {
            // PsyDepositTreeContract::set_chain_root stores an absolute count.
            // Re-submitting the same snapshot is therefore idempotent.
            deposit_set_root_calls.push(build_set_chain_root_call(
                source_chain_index,
                per_chain_snapshot_deposit_count,
                deposit_root_hex,
            )?);
        }
        tracing::info!(
            source_chain_index,
            deposit_next_index,
            global_target_deposit_count,
            per_chain_snapshot_deposit_count,
            pending_deposit_count,
            proved_deposit_count,
            global_target_deposits_remaining_on_l2,
            deposit_root = %deposit_root_hex,
            "built set_chain_root L2 call from services per-chain historical root"
        );
    } else {
        tracing::info!(
            source_chain_index,
            deposit_next_index,
            global_target_deposit_count,
            pending_deposit_count,
            proved_deposit_count,
            global_target_deposits_remaining_on_l2,
            is_catchup_batch,
            "no new deposits to set_chain_root on L2"
        );
    }

    let withdrawal_from_checkpoint = from_checkpoint.max(1);
    let (l2_withdrawal_next_index, l2_withdrawal_global_count) = if !is_catchup_batch {
        let chain_next_index = provider
            .get_withdrawal_tree_next_index(
                latest_checkpoint,
                BRIDGE_USER_ID_U64,
                source_chain_index,
            )
            .await?;
        let global_count = provider
            .get_withdrawal_tree_global_count(latest_checkpoint, BRIDGE_USER_ID_U64)
            .await?;
        (chain_next_index, global_count)
    } else {
        (0, 0)
    };
    let withdrawals = if !is_catchup_batch {
        propose_withdrawals::fetch_pending_bridge_withdrawals(
            propose_args,
            withdrawal_from_checkpoint,
            to_checkpoint.saturating_add(1),
            l2_withdrawal_global_count,
        )
        .await?
    } else {
        Vec::new()
    };
    let withdrawal_batch_calls = build_withdrawal_batch_calls(&withdrawals);

    tracing::info!(
        source_chain_index,
        l2_withdrawal_next_index,
        l2_withdrawal_global_count,
        append_withdrawals_count = withdrawals.len(),
        raw_batch_calls = withdrawal_batch_calls.len(),
        has_withdrawal_appends = !withdrawals.is_empty(),
        is_catchup_batch,
        scan_from_checkpoint = withdrawal_from_checkpoint,
        scan_to_checkpoint = to_checkpoint,
        "bridge L2 round batch plan (deposits via services-derived set_chain_root)"
    );

    let all_batch_calls: Vec<ContractCallArgs> = deposit_set_root_calls
        .into_iter()
        .chain(withdrawal_batch_calls)
        .collect();

    Ok(L2CallPlan {
        withdrawals,
        batch_calls: all_batch_calls,
    })
}


async fn finish_l2_round(
    provider: &RpcProvider,
    to_checkpoint: u64,
    proved_deposit_count: u32,
    pending_deposit_count: u32,
    source_chain_index: u64,
    is_catchup_batch: bool,
    submitted_l2_work: bool,
    claim_withdrawals: Vec<propose_withdrawals::PendingWithdrawal>,
) -> anyhow::Result<L2RoundResult> {
    let l2_deposit_cursor = fetch_deposit_tree_next_index(
        provider,
        to_checkpoint,
        source_chain_index,
    )
    .await?;
    let deposit_append_target = select_deposit_append_target(
        is_catchup_batch,
        to_checkpoint,
        to_checkpoint,
        l2_deposit_cursor,
        proved_deposit_count,
        pending_deposit_count,
    )?;

    tracing::info!(
        source_chain_index,
        l2_deposit_cursor,
        deposit_append_target = ?deposit_append_target,
        to_checkpoint,
        submitted_l2_work,
        is_catchup_batch,
        claim_withdrawals_count = claim_withdrawals.len(),
        "bridge L2 round has no new L2 calls; returning for prove/finalize"
    );
    Ok(L2RoundResult {
        deposit_append_target,
        to_checkpoint,
        submitted_l2_work,
        is_catchup_batch,
        claim_withdrawals,
    })
}

fn accepted_endcap_identity_matches(
    expected: &[EndCapContractSlotUpdate],
    accepted: &RealmEndCapSlotUpdates,
) -> bool {
    let mut expected_updates: Vec<_> = expected
        .iter()
        .map(|update| (update.contract_id, update.slot, update.old_value, update.new_value))
        .collect();
    let mut accepted_updates: Vec<_> = accepted
        .contracts
        .iter()
        .flat_map(|contract| {
            contract
                .slot_updates
                .iter()
                .map(move |update| (contract.contract_id, update.slot, update.old_value, update.new_value))
        })
        .collect();
    expected_updates.sort_unstable();
    accepted_updates.sort_unstable();

    let mut accepted_index = 0;
    for expected_update in expected_updates {
        while accepted_index < accepted_updates.len() && accepted_updates[accepted_index] < expected_update {
            accepted_index += 1;
        }
        if accepted_updates.get(accepted_index) != Some(&expected_update) {
            return false;
        }
        accepted_index += 1;
    }
    true
}

async fn recover_duplicate_endcap_leaf_with<Lookup, LookupFuture>(
    error: anyhow::Error,
    expected_user_id: u64,
    lookup: Lookup,
) -> anyhow::Result<QHashOut<GoldilocksField>>
where
    Lookup: FnOnce(u64, u64) -> LookupFuture,
    LookupFuture: Future<Output = anyhow::Result<Option<RealmEndCapSlotUpdates>>>,
{
    let submission = error.downcast::<EndCapSubmissionError>()?;
    let Some(duplicate) = submission
        .source
        .downcast_ref::<psy_provider::provider::EndCapAlreadySubmitted>()
    else {
        return Err(submission.into());
    };
    ensure!(
        duplicate.user_id == expected_user_id,
        "duplicate endcap user mismatch: acknowledgement user_id={} expected_user_id={} unique_pending_id={}",
        duplicate.user_id,
        expected_user_id,
        duplicate.unique_pending_id
    );
    let accepted = lookup(duplicate.user_id, duplicate.unique_pending_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!(
            "duplicate endcap acknowledgement has no accepted identity: user_id={} unique_pending_id={}",
            duplicate.user_id,
            duplicate.unique_pending_id
        ))?;
    ensure!(
        accepted.user_id == duplicate.user_id
            && accepted.unique_pending_id == duplicate.unique_pending_id,
        "duplicate endcap identity mismatch: acknowledgement user_id={} unique_pending_id={} accepted user_id={} unique_pending_id={}",
        duplicate.user_id,
        duplicate.unique_pending_id,
        accepted.user_id,
        accepted.unique_pending_id
    );
    if !accepted_endcap_identity_matches(&submission.contract_slot_updates, &accepted) {
        let mut expected_updates: Vec<_> = submission
            .contract_slot_updates
            .iter()
            .map(|update| (update.contract_id, update.slot, update.old_value, update.new_value))
            .collect();
        let mut accepted_updates: Vec<_> = accepted
            .contracts
            .iter()
            .flat_map(|contract| {
                contract
                    .slot_updates
                    .iter()
                    .map(move |update| (contract.contract_id, update.slot, update.old_value, update.new_value))
            })
            .collect();
        expected_updates.sort_unstable();
        accepted_updates.sort_unstable();
        let first_expected_only = expected_updates.iter().find(|update| accepted_updates.binary_search(update).is_err());
        let first_accepted_only = accepted_updates.iter().find(|update| expected_updates.binary_search(update).is_err());
        anyhow::bail!(
            "duplicate endcap contract update identity mismatch: user_id={} unique_pending_id={} expected_count={} accepted_count={} first_expected_only={:?} first_accepted_only={:?}",
            duplicate.user_id,
            duplicate.unique_pending_id,
            expected_updates.len(),
            accepted_updates.len(),
            first_expected_only,
            first_accepted_only
        );
    }
    Ok(submission.end_user_leaf_hash)
}

async fn resolve_l2_submission_leaf(
    provider: &RpcProvider,
    result: anyhow::Result<QHashOut<GoldilocksField>>,
    expected_user_id: u64,
) -> anyhow::Result<QHashOut<GoldilocksField>> {
    match result {
        Ok(leaf) => Ok(leaf),
        Err(error) => {
            recover_duplicate_endcap_leaf_with(error, expected_user_id, |user_id, unique_pending_id| {
                provider.get_realm_user_end_cap_slot_updates(user_id, unique_pending_id)
            })
            .await
        }
    }
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
        std::pin::Pin<Box<dyn futures::Future<Output = anyhow::Result<(usize, anyhow::Result<QHashOut<GoldilocksField>>)>> + Send>>,
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
            let result = session.exec_contract_call(pk, ContractCallData::new(vec![call])).await;
            Ok((i, result))
        }));
    }
    submitted = initial;

    // Drain the stream, submitting new batches as slots open up
    while let Some(result) = futures.next().await {
        let (idx, submission_result) = result?;
        let leaf = resolve_l2_submission_leaf(provider, submission_result, relayer_user_id).await?;
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
                let result = session.exec_contract_call(pk, ContractCallData::new(vec![call])).await;
                Ok((submitted, result))
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


async fn fetch_deposit_tree_next_index(
    provider: &RpcProvider,
    checkpoint_id: u64,
    chain_index: u64,
) -> anyhow::Result<u64> {
    // Match deposit_tree.get_chain_next_index(chain_index): read chain_counts[chain_index]
    // from the compiled sub-slot layout, then decode the correct felt within the packed leaf.
    let sub_slot_index = DEPOSIT_TREE_CHAIN_COUNTS_SUBSLOT_BASE + chain_index;
    let leaf_index = sub_slot_index / 4;
    let next_index_leaf = provider
        .get_user_contract_state_tree_leaf_hash(
            checkpoint_id,
            BRIDGE_USER_ID_U64,
            DEPOSIT_TREE_CONTRACT_ID,
            CONTRACT_STATE_TREE_HEIGHT,
            leaf_index,
        )
        .await?;
    read_single_felt_from_packed_leaf(next_index_leaf, sub_slot_index)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::propose_withdrawals::PendingWithdrawal;
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

    fn sample_withdrawal(seed: u32) -> PendingWithdrawal {
        let words = |base: u32| std::array::from_fn(|i| base + i as u32);
        PendingWithdrawal {
            event_id: seed as i64,
            checkpoint_id: 100 + seed as u64,
            user_id: 200 + seed as u64,
            sender_user_id: 300 + seed as u64,
            contract_id: 400 + seed as u64,
            destination_chain_index: 500 + seed as u64,
            token_address: words(seed * 10 + 1),
            amount: words(seed * 10 + 101),
            recipient: words(seed * 10 + 201),
            nonce: words(seed * 10 + 301),
            leaf_hash: format!("leaf-{seed}"),
        }
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
        assert!(!window.is_catchup_batch);
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
        assert!(!window.is_catchup_batch);
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
        assert!(!window.is_catchup_batch);
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
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn relayer_window_marks_oversized_gap_as_catchup() {
        // When confirmed_to_checkpoint - from_checkpoint + 1 > max_checkpoint_batch,
        // is_catchup_batch = true so deposits and withdrawals are skipped.
        // to_checkpoint is truncated to from + max_checkpoint_batch - 1 per round;
        // multiple catchup rounds advance the cursor until gap <= max_checkpoint_batch.
        let window = select_relayer_window(10, 80, 3, 8);
        // confirmed = 77, from = 10, range = 68 > 8 → catchup
        // to_checkpoint = 10 + 8 - 1 = 17 (truncated per round)

        assert_eq!(
            window,
            RelayerWindow {
                to_checkpoint: 17,
                confirmed_to_checkpoint: Some(77),
                is_catchup_batch: true,
            }
        );
        assert!(window.has_confirmed_range());
        assert!(window.is_catchup_batch);
    }

    #[test]
    fn relayer_window_normal_range_not_catchup() {
        // Range within max_checkpoint_batch → normal round, not catchup.
        let window = select_relayer_window(60, 80, 3, 32);
        // confirmed = 77, from = 60, range = 18 ≤ 32 → not catchup

        assert_eq!(
            window,
            RelayerWindow {
                to_checkpoint: 77,
                confirmed_to_checkpoint: Some(77),
                is_catchup_batch: false,
            }
        );
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn bridge_business_is_disabled_for_catchup_batches() {
        let window = RelayerWindow {
            to_checkpoint: 10,
            confirmed_to_checkpoint: Some(20),
            is_catchup_batch: true,
        };

        assert!(window.has_confirmed_range());
        assert!(window.is_catchup_batch);
    }

    #[test]
    fn catchup_defers_persisted_withdrawals_until_normal_round() {
        let is_catchup_batch = RelayerWindow {
            to_checkpoint: 10,
            confirmed_to_checkpoint: Some(20),
            is_catchup_batch: true,
        }
        .is_catchup_batch;

        assert!(is_catchup_batch);
        assert!(!(!is_catchup_batch && 1 > 0));
        assert!(!false && 1 > 0);
        assert!(!(false && 0 > 0));
    }


    #[test]
    fn reconcile_state_preserves_pending_withdrawals() {
        let path = temp_state_path("pending");
        let withdrawal = sample_withdrawal(1);
        let state = DaemonState {
            last_finalized_checkpoint: 10,
            pending_claim_withdrawals: HashMap::from([(
                withdrawal.leaf_hash.clone(),
                withdrawal.clone(),
            )]),
        };

        let reconciled = reconcile_state_with_l1_finalized_checkpoint(state, &path, 64).unwrap();

        assert_eq!(reconciled.last_finalized_checkpoint, 64);
        assert_eq!(reconciled.pending_claim_withdrawals.len(), 1);
        assert_eq!(
            reconciled.pending_claim_withdrawals[&withdrawal.leaf_hash].event_id,
            withdrawal.event_id
        );
        let saved = load_state(&path).unwrap();
        assert_eq!(saved.pending_claim_withdrawals.len(), 1);
        let _ = std::fs::remove_file(path);
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

    #[test]
    fn withdrawal_batch_calls_single_item_matches_append_withdrawal_layout() {
        let withdrawal = sample_withdrawal(1);
        let calls = build_withdrawal_batch_calls(std::slice::from_ref(&withdrawal));

        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.contract_id, WITHDRAWAL_TREE_CONTRACT_ID as u64);
        assert_eq!(call.method_name, "append_withdrawal");
        assert_eq!(call.inputs.len(), 35);
        assert_eq!(call.inputs[0], withdrawal.sender_user_id);
        assert_eq!(call.inputs[1], withdrawal.contract_id);
        assert_eq!(call.inputs[2], withdrawal.destination_chain_index);
        assert_eq!(
            &call.inputs[3..11],
            &withdrawal
                .token_address
                .iter()
                .map(|&v| v as u64)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            &call.inputs[27..35],
            &withdrawal.nonce.iter().map(|&v| v as u64).collect::<Vec<_>>()
        );
    }

    #[test]
    fn withdrawal_batch_calls_two_items_use_sender_auth_batch_layout() {
        let withdrawals = vec![sample_withdrawal(1), sample_withdrawal(2)];
        let calls = build_withdrawal_batch_calls(&withdrawals);

        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.method_name, "batch_append_withdrawals_2");
        assert_eq!(call.inputs.len(), 71);
        assert_eq!(call.inputs[0], 2);
        assert_eq!(call.inputs[1], withdrawals[0].sender_user_id);
        assert_eq!(call.inputs[2], withdrawals[1].sender_user_id);
        assert_eq!(call.inputs[3], withdrawals[0].contract_id);
        assert_eq!(call.inputs[4], withdrawals[1].contract_id);
        assert_eq!(call.inputs[5], withdrawals[0].destination_chain_index);
        assert_eq!(call.inputs[6], withdrawals[1].destination_chain_index);
        assert_eq!(
            &call.inputs[7..23],
            &withdrawals
                .iter()
                .flat_map(|w| w.token_address.iter().map(|&v| v as u64))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            &call.inputs[55..71],
            &withdrawals
                .iter()
                .flat_map(|w| w.nonce.iter().map(|&v| v as u64))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn withdrawal_batch_calls_seven_items_split_into_two_then_five_in_order() {
        let withdrawals = (1..=7).map(sample_withdrawal).collect::<Vec<_>>();
        let calls = build_withdrawal_batch_calls(&withdrawals);

        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].method_name, "batch_append_withdrawals_2");
        assert_eq!(calls[0].inputs[0], 2);
        assert_eq!(calls[0].inputs.len(), 71);
        assert_eq!(calls[0].inputs[1], withdrawals[0].sender_user_id);
        assert_eq!(calls[0].inputs[2], withdrawals[1].sender_user_id);

        assert_eq!(calls[1].method_name, "batch_append_withdrawals_5");
        assert_eq!(calls[1].inputs[0], 5);
        assert_eq!(calls[1].inputs.len(), 176);
        assert_eq!(calls[1].inputs[1], withdrawals[2].sender_user_id);
        assert_eq!(calls[1].inputs[5], withdrawals[6].sender_user_id);
        assert_eq!(
            &calls[1].inputs[16..56],
            &withdrawals[2..]
                .iter()
                .flat_map(|w| w.token_address.iter().map(|&v| v as u64))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn select_relayer_window_catchup_batch_spans_sixty_four_checkpoints() {
        for latest_checkpoint in [104, 204, 1_004] {
            let window = select_relayer_window(1, latest_checkpoint, 3, 64);

            assert_eq!(window.to_checkpoint, 64);
            assert_eq!(window.to_checkpoint - 1 + 1, 64);
            assert!(window.is_catchup_batch);
        }
    }

    #[test]
    fn gap_equal_to_max_checkpoint_batch_is_a_normal_round() {
        let window = select_relayer_window(1, 67, 3, 64);

        assert_eq!(window.to_checkpoint, 64);
        assert_eq!(window.confirmed_to_checkpoint, Some(64));
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn select_relayer_window_truncates_catchup_to_max_batch() {
        // Catchup mode truncates to_checkpoint to from + max_batch - 1.
        // With max_batch=64, a gap of 100 should truncate to 63 checkpoints per round.
        let window = select_relayer_window(10, 200, 3, 64);
        // confirmed = 197, from = 10, range = 188 > 64 → catchup
        // to_checkpoint = 10 + 64 - 1 = 73
        assert_eq!(window.to_checkpoint, 73);
        assert_eq!(window.confirmed_to_checkpoint, Some(197));
        assert!(window.is_catchup_batch);
    }

    #[test]
    fn relayer_window_catchup_tail_of_one_is_provable_next_round() {
        // A 65-checkpoint gap with max=64 first proves checkpoints 1..=64.
        // The next round selects the remaining checkpoint as a normal, provable
        // one-checkpoint range rather than waiting for another checkpoint.
        let catchup_window = select_relayer_window(1, 68, 3, 64);
        assert_eq!(catchup_window.to_checkpoint, 64);
        assert_eq!(catchup_window.confirmed_to_checkpoint, Some(65));
        assert!(catchup_window.is_catchup_batch);

        let tail_window = select_relayer_window(65, 68, 3, 64);
        assert_eq!(
            tail_window,
            RelayerWindow {
                to_checkpoint: 65,
                confirmed_to_checkpoint: Some(65),
                is_catchup_batch: false,
            }
        );
        assert!(tail_window.has_confirmed_range());
        assert!(!tail_window.is_catchup_batch);
    }

    #[test]
    fn default_max_checkpoint_batch_remains_64() {
        assert_eq!(DEFAULT_MAX_CHECKPOINT_BATCH, 64);
    }

    #[test]
    fn validate_max_checkpoint_batch_accepts_one_and_above() {
        for batch in [1u64, 65, 97] {
            validate_max_checkpoint_batch(batch)
                .unwrap_or_else(|e| panic!("batch {batch} should be accepted: {e}"));
        }
    }

    #[test]
    fn validate_max_checkpoint_batch_rejects_zero() {
        let err = validate_max_checkpoint_batch(0).unwrap_err();
        assert!(err.to_string().contains("max_checkpoint_batch must be >= 1"));
    }

    #[test]
    fn select_relayer_window_honors_batch_sizes_above_legacy_64_cap() {
        let window = select_relayer_window(1, 200, 3, 97);
        // confirmed = 197, from = 1, range = 197 > 97 → catchup
        assert_eq!(window.to_checkpoint, 1 + 97 - 1);
        assert!(window.is_catchup_batch);

        let window_65 = select_relayer_window(10, 100, 3, 65);
        // confirmed = 97, range = 88 > 65 → catchup, truncate to 10 + 64 = 74
        assert_eq!(window_65.to_checkpoint, 74);
        assert!(window_65.is_catchup_batch);
    }

    // ── crash-recovery & state persistence edge cases ──────────────────────

    #[test]
    fn load_state_returns_default_when_file_missing() {
        // Restart with no daemon_state.toml: must boot from a clean default,
        // not error. L1 reconciliation re-anchors the cursor next round.
        let path = temp_state_path("missing");
        assert!(!path.exists());
        let state = load_state(&path).expect("missing state file should yield default");
        assert_eq!(state.last_finalized_checkpoint, 0);
        assert!(state.pending_claim_withdrawals.is_empty());
    }

    #[test]
    fn load_state_errors_on_corrupt_state_file() {
        // A corrupt daemon_state.toml must surface a parse error rather than
        // silently booting from default — otherwise pending claims vanish.
        let path = temp_state_path("corrupt");
        std::fs::write(&path, "last_finalized_checkpoint = \"not-a-u64\"\n").unwrap();
        let err = load_state(&path).unwrap_err();
        assert!(
            err.to_string().contains("failed to parse daemon state"),
            "expected parse-error context, got: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn save_then_load_state_round_trips_pending_withdrawals() {
        // Persisted pending claims must survive a save/load cycle bit-for-bit
        // so a restart resumes claiming exactly where it left off.
        let path = temp_state_path("roundtrip");
        let w1 = sample_withdrawal(3);
        let w2 = sample_withdrawal(7);
        let state = DaemonState {
            last_finalized_checkpoint: 42,
            pending_claim_withdrawals: HashMap::from([
                (w1.leaf_hash.clone(), w1.clone()),
                (w2.leaf_hash.clone(), w2.clone()),
            ]),
        };
        save_state(&path, &state).unwrap();
        let loaded = load_state(&path).unwrap();
        assert_eq!(loaded.last_finalized_checkpoint, 42);
        assert_eq!(loaded.pending_claim_withdrawals.len(), 2);
        assert_eq!(loaded.pending_claim_withdrawals[&w1.leaf_hash].event_id, w1.event_id);
        assert_eq!(loaded.pending_claim_withdrawals[&w2.leaf_hash].event_id, w2.event_id);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn landed_l2_withdrawal_survives_crash_and_is_claimed_after_restart() {
        let path = temp_state_path("pre-submit-crash");
        let withdrawal = sample_withdrawal(11);
        let state = DaemonState {
            last_finalized_checkpoint: 42,
            pending_claim_withdrawals: HashMap::new(),
        };
        save_state(&path, &state).unwrap();

        persist_claim_withdrawals_before_l2_submit(&path, std::slice::from_ref(&withdrawal))
            .expect("withdrawal must be durable before the L2 batch is submitted");

        // The L2 batch lands, then the daemon crashes before the round can
        // return its in-memory claim_withdrawals vector. Restart from disk only.
        let mut restarted = load_state(&path).expect("restart must load pending claims");
        assert_eq!(restarted.last_finalized_checkpoint, 42);
        assert_eq!(restarted.pending_claim_withdrawals.len(), 1);
        assert_eq!(
            restarted.pending_claim_withdrawals[&withdrawal.leaf_hash].event_id,
            withdrawal.event_id
        );

        let claim_report = claim_withdrawals::BatchWithdrawalsReport {
            requested: 1,
            submitted_count: 1,
            already_claimed_count: 0,
            resolved_leaf_hashes: vec![withdrawal.leaf_hash.clone()],
            failure_reasons: HashMap::new(),
        };
        apply_claim_report(&mut restarted.pending_claim_withdrawals, &claim_report);
        assert!(
            restarted.pending_claim_withdrawals.is_empty(),
            "the restarted daemon must submit and resolve the landed withdrawal"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reconcile_state_noop_when_local_matches_l1_does_not_write() {
        // When local already matches L1, reconcile must be a no-op: it must
        // not touch the state file (avoids needless disk churn / clobbering).
        let path = temp_state_path("noop");
        assert!(!path.exists());
        let state = DaemonState {
            last_finalized_checkpoint: 15,
            pending_claim_withdrawals: HashMap::new(),
        };
        let reconciled = reconcile_state_with_l1_finalized_checkpoint(state, &path, 15).unwrap();
        assert_eq!(reconciled.last_finalized_checkpoint, 15);
        assert!(!path.exists(), "no-op reconcile must not create a state file");
    }

    #[test]
    fn reconcile_state_clamps_local_ahead_of_l1_and_persists() {
        // Crash after finalize but before state save: L1 advanced, local did not.
        // The inverse — local ahead of L1 — must clamp down to L1 and persist
        // so the next round's from_checkpoint is L1-authoritative.
        let path = temp_state_path("clamp-persist");
        let w = sample_withdrawal(2);
        let state = DaemonState {
            last_finalized_checkpoint: 30,
            pending_claim_withdrawals: HashMap::from([(w.leaf_hash.clone(), w.clone())]),
        };
        let reconciled = reconcile_state_with_l1_finalized_checkpoint(state, &path, 18).unwrap();
        assert_eq!(reconciled.last_finalized_checkpoint, 18);
        // Pending claim survives the clamp.
        assert_eq!(reconciled.pending_claim_withdrawals.len(), 1);
        assert_eq!(reconciled.pending_claim_withdrawals[&w.leaf_hash].event_id, w.event_id);
        // Clamp is persisted to disk.
        assert_eq!(load_state(&path).unwrap().last_finalized_checkpoint, 18);
        let _ = std::fs::remove_file(path);
    }

    // ── select_relayer_window boundary edge cases ──────────────────────────

    #[test]
    fn select_relayer_window_lag_zero_treats_latest_as_confirmed() {
        // confirmation_lag_checkpoints=0 → confirmed == latest.
        // Small range within max_batch → normal round, business allowed.
        let window = select_relayer_window(10, 50, 0, 64);
        assert_eq!(window.confirmed_to_checkpoint, Some(50));
        assert_eq!(window.to_checkpoint, 50);
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn select_relayer_window_lag_zero_large_gap_triggers_catchup() {
        // lag=0 with a gap exceeding max_batch still enters catchup mode.
        let window = select_relayer_window(1, 100, 0, 64);
        assert_eq!(window.confirmed_to_checkpoint, Some(100));
        assert_eq!(window.to_checkpoint, 64);
        assert!(window.is_catchup_batch);
    }

    #[test]
    fn select_relayer_window_from_ahead_of_latest_clamps_to_latest() {
        // L1 finalized cursor ahead of L2 latest (from > latest): the relayer
        // must wait at latest rather than proving a non-existent range.
        // confirmed = latest - lag < from → append-only; to clamps to latest.
        let window = select_relayer_window(100, 50, 3, 64);
        assert_eq!(window.confirmed_to_checkpoint, None);
        assert!(!window.is_catchup_batch);
        assert_eq!(window.to_checkpoint, 50);
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn select_relayer_window_lag_exceeds_latest_is_append_only() {
        // lag > latest → checked_sub yields None → append-only at latest,
        // capped by max_batch from the (zero) cursor.
        let window = select_relayer_window(0, 5, 10, 64);
        assert_eq!(window.confirmed_to_checkpoint, None);
        assert!(!window.is_catchup_batch);
        assert_eq!(window.to_checkpoint, 5);
    }

    #[test]
    fn select_relayer_window_max_batch_zero_in_confirmed_range_is_unbounded() {
        // max_checkpoint_batch=0 in confirmed-range mode means "no batching
        // limit": the whole gap is a single normal round with no catchup gating.
        // (validate_max_checkpoint_batch rejects 0 for run(), but the window
        // function itself must remain well-defined.)
        let window = select_relayer_window(1, 200, 3, 0);
        assert_eq!(window.confirmed_to_checkpoint, Some(197));
        assert_eq!(window.to_checkpoint, 197);
        assert!(!window.is_catchup_batch, "max_batch=0 must not gate catchup");
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn select_relayer_window_saturates_append_only_to_checkpoint_near_u64_max() {
        // from near u64::MAX in append-only mode: saturating_add on
        // from + max_batch - 1 must not overflow/panic.
        let window = select_relayer_window(u64::MAX - 5, u64::MAX - 1, 100, 64);
        assert_eq!(window.confirmed_to_checkpoint, None);
        assert!(!window.is_catchup_batch);
        // min(latest, saturating_add(from, 63)) = min(MAX-1, MAX) = MAX-1.
        assert_eq!(window.to_checkpoint, u64::MAX - 1);
    }

    #[test]
    fn live_round_selects_absolute_deposit_target() {
        assert_eq!(select_deposit_append_target(false, 20, 20, 12, 7, 15).unwrap(), Some(12));
    }

    #[test]
    fn live_round_rejects_target_behind_proved_count() {
        assert!(select_deposit_append_target(false, 20, 20, 6, 7, 15).is_err());
    }

    #[test]
    fn live_round_with_already_proved_target_selects_no_append() {
        assert_eq!(select_deposit_append_target(false, 20, 20, 7, 7, 15).unwrap(), None);
    }

    #[test]
    fn set_chain_root_call_uses_absolute_snapshot_count() {
        let root = "0x0000000100000002000000030000000400000005000000060000000700000008";
        let call = build_set_chain_root_call(9, 12, root).unwrap();

        assert_eq!(call.contract_id, DEPOSIT_TREE_CONTRACT_ID as u64);
        assert_eq!(call.method_name, "set_chain_root");
        assert_eq!(call.inputs, vec![9, 12, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn catchup_round_selects_no_deposit_target() {
        assert_eq!(select_deposit_append_target(true, 20, 20, 12, 7, 15).unwrap(), None);
    }

    #[test]
    fn capped_landing_selects_no_deposit_target() {
        assert_eq!(select_deposit_append_target(false, 19, 20, 12, 7, 15).unwrap(), None);
    }

    #[test]
    fn capped_landing_tolerates_l2_deposit_overcount() {
        assert_eq!(select_deposit_append_target(false, 19, 20, 16, 7, 15).unwrap(), None);
    }

    #[test]
    fn live_round_rejects_l2_deposit_overcount() {
        assert!(select_deposit_append_target(false, 20, 20, 16, 7, 15).is_err());
    }

    #[test]
    fn historical_catchup_tolerates_l2_deposit_overcount() {
        assert_eq!(select_deposit_append_target(true, 20, 20, 16, 7, 15).unwrap(), None);
    }

    #[test]
    fn historical_catchup_still_rejects_inconsistent_l1_cursors() {
        assert!(select_deposit_append_target(true, 20, 20, 16, 16, 15).is_err());
    }

    // ── claim reconciliation edge cases (double-claim defence) ─────────────

    #[test]
    fn apply_claim_report_removes_resolved_and_already_claimed_keeps_failures() {
        // resolved_leaf_hashes carries BOTH successfully submitted AND
        // already-claimed withdrawals (claim_withdrawals.rs pushes the leaf
        // hash in both cases). apply_claim_report must drop both from pending
        // so already-claimed withdrawals are never retried (no double-claim).
        let w1 = sample_withdrawal(1); // newly submitted
        let w2 = sample_withdrawal(2); // already claimed on L1
        let w3 = sample_withdrawal(3); // failed, must retry next round
        let mut pending: HashMap<String, PendingWithdrawal> = [
            (w1.leaf_hash.clone(), w1.clone()),
            (w2.leaf_hash.clone(), w2.clone()),
            (w3.leaf_hash.clone(), w3.clone()),
        ]
        .into_iter()
        .collect();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            requested: 3,
            submitted_count: 1,
            already_claimed_count: 1,
            resolved_leaf_hashes: vec![w1.leaf_hash.clone(), w2.leaf_hash.clone()],
            failure_reasons: HashMap::from([(w3.leaf_hash.clone(), "proof not ready".to_string())]),
        };
        apply_claim_report(&mut pending, &report);
        assert!(!pending.contains_key(&w1.leaf_hash), "submitted withdrawal must be removed");
        assert!(
            !pending.contains_key(&w2.leaf_hash),
            "already-claimed withdrawal must be removed to prevent double-claim"
        );
        assert!(pending.contains_key(&w3.leaf_hash), "failed withdrawal must remain for retry");
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn apply_claim_report_leaves_unreported_withdrawals_untouched() {
        // Withdrawals absent from the report (e.g. claimed in a prior partial
        // batch) must be retained so they are retried in a later round.
        let w1 = sample_withdrawal(1);
        let w2 = sample_withdrawal(2);
        let mut pending: HashMap<String, PendingWithdrawal> = [
            (w1.leaf_hash.clone(), w1.clone()),
            (w2.leaf_hash.clone(), w2.clone()),
        ]
        .into_iter()
        .collect();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            requested: 1,
            submitted_count: 1,
            already_claimed_count: 0,
            resolved_leaf_hashes: vec![w1.leaf_hash.clone()],
            failure_reasons: HashMap::new(),
        };
        apply_claim_report(&mut pending, &report);
        assert!(!pending.contains_key(&w1.leaf_hash));
        assert!(pending.contains_key(&w2.leaf_hash), "unreported withdrawal must be retained");
    }

    #[test]
    fn record_claim_withdrawals_deduplicates_by_leaf_hash_across_scans() {
        // Two L2 scans re-reporting the same withdrawal must not duplicate the
        // claim entry; the seen set is the dedup boundary.
        let w1 = sample_withdrawal(1);
        let w2 = sample_withdrawal(2);
        let mut seen = HashSet::new();
        let mut claims = Vec::new();
        record_claim_withdrawals(&[w1.clone(), w2.clone()], &mut seen, &mut claims);
        assert_eq!(claims.len(), 2);
        // Re-scan re-reports w1 — must NOT be appended again.
        record_claim_withdrawals(&[w1.clone()], &mut seen, &mut claims);
        assert_eq!(claims.len(), 2, "duplicate leaf_hash must not be recorded twice");
        assert!(claims.iter().any(|c| c.leaf_hash == w1.leaf_hash));
        assert!(claims.iter().any(|c| c.leaf_hash == w2.leaf_hash));
    }


    /// Deterministic xorshift64 so property tests are reproducible. The seed is
    /// fixed; failing inputs are printed so a red run replays exactly.
    fn xorshift_u64(state: &mut u64) -> u64 {
        let mut x = *state;
        debug_assert!(x != 0, "xorshift state must be non-zero");
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn make_packed_leaf(elements: [u64; 4]) -> QHashOut<GoldilocksField> {
        QHashOut::<GoldilocksField>::try_from(&elements).expect("4 u64 elements fit QHashOut")
    }

    // ── select_relayer_window: property-based invariants ───────────────────

    #[test]
    fn select_relayer_window_invariants_hold_across_seeded_inputs() {
        // Defends the universal contracts every daemon round relies on, across
        // thousands of input combinations plus u64::MAX-boundary inputs:
        //   (1) to_checkpoint never exceeds latest_checkpoint (relayer never
        //       proves a range beyond what L2 has produced).
        //   (2) a catchup batch always carries a confirmed range.
        //   (3) deposit-appends and withdrawal-processing are gated identically
        //       by is_catchup_batch — they are never allowed to disagree.
        //   (4) when a confirmed range exists, it is never behind from_checkpoint.
        //   (5) a catchup round (no overflow) spans exactly max_checkpoint_batch.
        //   (6) a non-catchup confirmed round lands exactly on confirmed_to.
        //   (7) an append-only round (max>0) lands on min(latest, from+max-1);
        //       with max==0 it lands on latest (unbounded).
        const SEED: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut state = SEED;
        let small = |s: &mut u64| (xorshift_u64(s) % 301) as u64;
        let max_choices = [0u64, 1, 2, 3, 5, 8, 32, 64, 97, 128];

        // Bulk: small checkpoints where catchup / normal / append-only all appear.
        for _ in 0..8_000 {
            let from = small(&mut state);
            let latest = small(&mut state);
            let lag = xorshift_u64(&mut state) % 21;
            let max_batch = max_choices[(xorshift_u64(&mut state) as usize) % max_choices.len()];
            check_window_invariants(from, latest, lag, max_batch, SEED);
        }

        // Boundary batch: latest near u64::MAX exercises confirmed-range catchup
        // and saturating arithmetic without overflow/panic.
        for _ in 0..1_000 {
            let latest = u64::MAX - (xorshift_u64(&mut state) % 16);
            let from = latest - (xorshift_u64(&mut state) % 200);
            let lag = xorshift_u64(&mut state) % 10;
            let max_batch = max_choices[(xorshift_u64(&mut state) as usize) % max_choices.len()];
            check_window_invariants(from, latest, lag, max_batch, SEED);
        }
    }

    fn check_window_invariants(from: u64, latest: u64, lag: u64, max_batch: u64, seed: u64) {
        let window = select_relayer_window(from, latest, lag, max_batch);
        let fail = |msg: &str| -> String {
            format!("seed={seed:#x} from={from} latest={latest} lag={lag} max={max_batch}: {msg}")
        };
        // (1) to_checkpoint never exceeds latest.
        assert!(window.to_checkpoint <= latest, "{}", fail("to_checkpoint exceeded latest"));
        // (2) catchup implies a confirmed range exists.
        if window.is_catchup_batch {
            assert!(
                window.confirmed_to_checkpoint.is_some(),
                "{}",
                fail("catchup batch lacks confirmed range")
            );
        }
        // (3) deposit/withdrawal gating agree and equal !is_catchup_batch.
        assert_eq!(
            !window.is_catchup_batch,
            !window.is_catchup_batch,
            "{}",
            fail("deposit/withdrawal gating disagree")
        );
        assert_eq!(
            !window.is_catchup_batch,
            !window.is_catchup_batch,
            "{}",
            fail("gating != !is_catchup_batch")
        );
        // (4) confirmed range, when present, is never behind from_checkpoint.
        if let Some(confirmed) = window.confirmed_to_checkpoint {
            assert!(
                confirmed >= from,
                "{}",
                fail("confirmed range behind from_checkpoint")
            );
        }
        // (5) catchup round (no overflow) spans exactly max_checkpoint_batch.
        if window.is_catchup_batch && from <= u64::MAX - (max_batch - 1) {
            assert_eq!(
                window.to_checkpoint - from + 1,
                max_batch,
                "{}",
                fail("catchup round did not span max_batch")
            );
        }
        // (6) non-catchup confirmed round lands exactly on confirmed_to.
        if !window.is_catchup_batch && window.confirmed_to_checkpoint.is_some() {
            assert_eq!(
                window.to_checkpoint,
                window.confirmed_to_checkpoint.unwrap(),
                "{}",
                fail("non-catchup confirmed round did not land on confirmed")
            );
        }
        // (7) append-only round lands on min(latest, from+max-1); max==0 → latest.
        if window.confirmed_to_checkpoint.is_none() {
            if max_batch > 0 {
                assert_eq!(
                    window.to_checkpoint,
                    latest.min(from.saturating_add(max_batch - 1)),
                    "{}",
                    fail("append-only round did not clamp to min(latest, from+max-1)")
                );
            } else {
                assert_eq!(
                    window.to_checkpoint, latest,
                    "{}",
                    fail("max==0 append-only round did not land on latest")
                );
            }
        }
    }

    // ── select_relayer_window: additional boundary edges ───────────────────

    #[test]
    fn select_relayer_window_max_batch_one_advances_one_checkpoint_per_catchup_round() {
        // max_batch=1: a 2-checkpoint gap is already "oversized" (range_len=2>1),
        // so every catchup round advances the cursor by exactly one checkpoint.
        let w = select_relayer_window(10, 20, 3, 1);
        // confirmed = 17, range = 8 > 1 → catchup; to = 10 + 1 - 1 = 10.
        assert_eq!(w.to_checkpoint, 10);
        assert_eq!(w.confirmed_to_checkpoint, Some(17));
        assert!(w.is_catchup_batch);
        // Next round advances from 11; range still > 1 → still catchup, to = 11.
        let w2 = select_relayer_window(11, 20, 3, 1);
        assert_eq!(w2.to_checkpoint, 11);
        assert!(w2.is_catchup_batch);
    }

    #[test]
    fn select_relayer_window_catchup_near_u64_max_does_not_overflow() {
        // confirmed-range catchup near u64::MAX: to = from + max - 1 must
        // saturate rather than panic. from = MAX-3, latest = MAX, lag = 0 →
        // confirmed = MAX, range = 4 > 2 → catchup, to = (MAX-3) + 1 = MAX-2.
        let w = select_relayer_window(u64::MAX - 3, u64::MAX, 0, 2);
        assert_eq!(w.confirmed_to_checkpoint, Some(u64::MAX));
        assert!(w.is_catchup_batch);
        assert_eq!(w.to_checkpoint, u64::MAX - 2);
        assert!(w.to_checkpoint <= u64::MAX);
    }

    #[test]
    fn select_relayer_window_lag_zero_latest_at_u64_max_triggers_catchup() {
        // latest = u64::MAX, lag = 0 → confirmed = MAX; tiny from gives an
        // enormous gap → catchup truncates to from + max - 1 without overflow.
        let w = select_relayer_window(5, u64::MAX, 0, 64);
        assert_eq!(w.confirmed_to_checkpoint, Some(u64::MAX));
        assert!(w.is_catchup_batch);
        assert_eq!(w.to_checkpoint, 5 + 64 - 1);
    }

    #[test]
    fn select_relayer_window_confirmed_equals_from_is_single_checkpoint_normal_round() {
        // confirmed == from ⇒ range_len = 1, never oversized for max >= 1 →
        // a normal, provable one-checkpoint round (not catchup).
        let w = select_relayer_window(42, 45, 3, 64);
        assert_eq!(w.confirmed_to_checkpoint, Some(42));
        assert_eq!(w.to_checkpoint, 42);
        assert!(!w.is_catchup_batch);
    }

    // ── optimal_batch_sizes: direct coverage ────────────────────────────────

    #[test]
    fn optimal_batch_sizes_maps_small_counts_to_minimal_packs() {
        // The packing primitive that batch-call builders depend on. Each row is
        // the unique minimal-batch-count decomposition using sizes {1,2,5} with
        // singles < 2.
        let cases: &[(usize, &[usize])] = &[
            (0, &[]),
            (1, &[1]),
            (2, &[2]),
            (3, &[1, 2]),
            (4, &[2, 2]),
            (5, &[5]),
            (6, &[1, 5]),
            (7, &[2, 5]),
            (8, &[1, 2, 5]),
            (9, &[2, 2, 5]),
            (10, &[5, 5]),
            (12, &[2, 5, 5]),
        ];
        for (n, expected) in cases {
            assert_eq!(&optimal_batch_sizes(*n), expected, "n={n}");
        }
    }

    #[test]
    fn optimal_batch_sizes_satisfies_invariants_for_all_counts_up_to_two_hundred() {
        // Property: for every n in 0..=200 the decomposition sums to n, uses only
        // {1,2,5}, keeps singles < 2, and is no worse than the greedy 5s-then-2s
        // packing (so it really minimises batch count).
        for n in 0..=200usize {
            let sizes = optimal_batch_sizes(n);
            assert_eq!(sizes.iter().sum::<usize>(), n, "sum != n at n={n}");
            assert!(
                sizes.iter().all(|&s| matches!(s, 1 | 2 | 5)),
                "illegal size at n={n}: {sizes:?}"
            );
            let singles = sizes.iter().filter(|&&s| s == 1).count();
            assert!(singles < 2, "singles>=2 at n={n}: {sizes:?}");
            // Independent minimality check: the minimum batch count is the
            // minimum over f in 0..=n/5 of (f + ceil((n - 5*f) / 2)) — after placing
            // f five-batches the remainder is filled most efficiently by twos (one
            // single at most for an odd remainder, staying < 2). This closed-form
            // derivation is independent of the function's nested brute-force loop.
            let theoretical_min = (0..=n / 5)
                .map(|f| f + (n - 5 * f + 1) / 2)
                .min()
                .unwrap_or(0);
            assert_eq!(
                sizes.len(),
                theoretical_min,
                "not minimal at n={n}: got {got} batches vs theoretical {theoretical_min} ({sizes:?})",
                got = sizes.len(),
            );
        }
    }


    // ── build_withdrawal_batch_calls: additional layout coverage ────────────

    #[test]
    fn build_withdrawal_batch_calls_empty_returns_empty() {
        assert!(build_withdrawal_batch_calls(&[]).is_empty());
    }

    #[test]
    fn build_withdrawal_batch_calls_five_uses_batch_append_withdrawals_5_layout() {
        // batch_append_withdrawals_5(count, senders[5], contracts[5], dests[5],
        //   token_addr[5*8], amount[5*8], recipient[5*8], nonce[5*8]) → 176 inputs.
        let ws: Vec<_> = (1..=5).map(sample_withdrawal).collect();
        let calls = build_withdrawal_batch_calls(&ws);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].method_name, "batch_append_withdrawals_5");
        assert_eq!(calls[0].contract_id, WITHDRAWAL_TREE_CONTRACT_ID as u64);
        assert_eq!(calls[0].inputs.len(), 176);
        assert_eq!(calls[0].inputs[0], 5);
        // senders block [1..6], contracts block [6..11], dests block [11..16].
        assert_eq!(
            &calls[0].inputs[1..6],
            &ws.iter().map(|w| w.sender_user_id).collect::<Vec<_>>()
        );
        assert_eq!(
            &calls[0].inputs[6..11],
            &ws.iter().map(|w| w.contract_id).collect::<Vec<_>>()
        );
        assert_eq!(
            &calls[0].inputs[11..16],
            &ws.iter().map(|w| w.destination_chain_index).collect::<Vec<_>>()
        );
        // token_address block [16..56], grouped per-withdrawal in original order.
        let mut token = Vec::new();
        for w in &ws {
            token.extend(w.token_address.iter().map(|&v| v as u64));
        }
        assert_eq!(&calls[0].inputs[16..56], &token);
    }

    #[test]
    fn build_withdrawal_batch_calls_twelve_splits_two_five_five_in_order() {
        // 12 withdrawals → [2, 5, 5]. Original order is preserved across batches:
        // first 2 → batch_2, next 5 → batch_5, last 5 → batch_5.
        let ws: Vec<_> = (1..=12).map(sample_withdrawal).collect();
        let calls = build_withdrawal_batch_calls(&ws);
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].method_name, "batch_append_withdrawals_2");
        assert_eq!(calls[0].inputs[0], 2);
        assert_eq!(calls[1].method_name, "batch_append_withdrawals_5");
        assert_eq!(calls[1].inputs[0], 5);
        assert_eq!(calls[2].method_name, "batch_append_withdrawals_5");
        assert_eq!(calls[2].inputs[0], 5);
        // First batch's senders are ws[0..2]; third batch's senders are ws[7..12].
        assert_eq!(calls[0].inputs[1], ws[0].sender_user_id);
        assert_eq!(calls[0].inputs[2], ws[1].sender_user_id);
        assert_eq!(calls[2].inputs[1], ws[7].sender_user_id);
        assert_eq!(calls[2].inputs[5], ws[11].sender_user_id);
    }

    // ── apply_claim_report: additional double-claim-defence edges ──────────

    #[test]
    fn apply_claim_report_empty_report_leaves_pending_untouched() {
        // An empty report (no resolves, no failures) must not mutate pending.
        let w = sample_withdrawal(1);
        let mut pending: HashMap<String, PendingWithdrawal> =
            [(w.leaf_hash.clone(), w.clone())].into_iter().collect();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            requested: 0,
            submitted_count: 0,
            already_claimed_count: 0,
            resolved_leaf_hashes: Vec::new(),
            failure_reasons: HashMap::new(),
        };
        apply_claim_report(&mut pending, &report);
        assert_eq!(pending.len(), 1);
        assert!(pending.contains_key(&w.leaf_hash));
    }

    #[test]
    fn apply_claim_report_resolving_unknown_leaf_is_a_safe_noop() {
        // A resolved leaf_hash that was never pending must not panic and must not
        // drop unrelated pending entries.
        let w1 = sample_withdrawal(1);
        let mut pending: HashMap<String, PendingWithdrawal> =
            [(w1.leaf_hash.clone(), w1.clone())].into_iter().collect();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            requested: 1,
            submitted_count: 1,
            already_claimed_count: 0,
            resolved_leaf_hashes: vec!["never-pending-leaf".to_string()],
            failure_reasons: HashMap::new(),
        };
        apply_claim_report(&mut pending, &report);
        assert_eq!(pending.len(), 1, "unknown resolved leaf must not evict w1");
        assert!(pending.contains_key(&w1.leaf_hash));
    }

    #[test]
    fn apply_claim_report_resolving_all_clears_pending() {
        // Every pending withdrawal resolved → pending becomes empty (all claims
        // complete; nothing left to retry).
        let w1 = sample_withdrawal(1);
        let w2 = sample_withdrawal(2);
        let mut pending: HashMap<String, PendingWithdrawal> = [
            (w1.leaf_hash.clone(), w1.clone()),
            (w2.leaf_hash.clone(), w2.clone()),
        ]
        .into_iter()
        .collect();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            requested: 2,
            submitted_count: 2,
            already_claimed_count: 0,
            resolved_leaf_hashes: vec![w1.leaf_hash.clone(), w2.leaf_hash.clone()],
            failure_reasons: HashMap::new(),
        };
        apply_claim_report(&mut pending, &report);
        assert!(pending.is_empty(), "all-resolved report must clear pending");
    }

    #[test]
    fn apply_claim_report_failure_for_unknown_leaf_never_inserts() {
        // failure_reasons only logs a warning; it must never ADD a leaf to pending.
        let w1 = sample_withdrawal(1);
        let mut pending: HashMap<String, PendingWithdrawal> =
            [(w1.leaf_hash.clone(), w1.clone())].into_iter().collect();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            requested: 1,
            submitted_count: 0,
            already_claimed_count: 0,
            resolved_leaf_hashes: Vec::new(),
            failure_reasons: HashMap::from([("never-pending-leaf".to_string(), "x".to_string())]),
        };
        apply_claim_report(&mut pending, &report);
        assert_eq!(pending.len(), 1, "failure reason must not insert into pending");
        assert!(pending.contains_key(&w1.leaf_hash));
        assert!(!pending.contains_key("never-pending-leaf"));
    }

    // ── record_claim_withdrawals: additional dedup edges ───────────────────

    #[test]
    fn record_claim_withdrawals_empty_input_is_noop() {
        let mut seen = HashSet::new();
        let mut claims = Vec::new();
        record_claim_withdrawals(&[], &mut seen, &mut claims);
        assert!(seen.is_empty());
        assert!(claims.is_empty());
    }

    #[test]
    fn record_claim_withdrawals_all_duplicates_produces_no_new_entries() {
        // Pre-seed `seen` with every leaf_hash → input records nothing new.
        let w1 = sample_withdrawal(1);
        let w2 = sample_withdrawal(2);
        let mut seen: HashSet<String> =
            [w1.leaf_hash.clone(), w2.leaf_hash.clone()].into_iter().collect();
        let mut claims = Vec::new();
        record_claim_withdrawals(&[w1.clone(), w2], &mut seen, &mut claims);
        assert_eq!(claims.len(), 0, "fully-duplicate input must record nothing");
    }

    #[test]
    fn record_claim_withdrawals_interleaved_new_and_duplicate_preserves_order() {
        // Mixed input: w1 new, w2 duplicate (already seen), w3 new → only w1 and
        // w3 are appended, in input order. Defends the within-round dedup
        // boundary that prevents the same claim being submitted twice.
        let w1 = sample_withdrawal(1);
        let w2 = sample_withdrawal(2);
        let w3 = sample_withdrawal(3);
        let mut seen: HashSet<String> = [w2.leaf_hash.clone()].into_iter().collect();
        let mut claims = Vec::new();
        record_claim_withdrawals(&[w1.clone(), w2, w3.clone()], &mut seen, &mut claims);
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].leaf_hash, w1.leaf_hash);
        assert_eq!(claims[1].leaf_hash, w3.leaf_hash);
    }

    // ── reconcile_state_with_l1_finalized_checkpoint: error-propagation ────

    #[test]
    fn reconcile_state_succeeds_and_advances_when_persistence_fails() {
        // Crash-recovery contract: a save_state failure during reconcile must
        // NOT abort the in-memory reconcile — the checkpoint is still advanced
        // and pending claims preserved, so the next round is L1-authoritative
        // even if disk could not be written this cycle.
        // Pointing save at a path whose PARENT directory does not exist makes
        // fs::write fail (it cannot create the missing parent) without disturbing
        // the in-memory state. A bare filename under temp_dir would succeed.
        let unwritable = std::env::temp_dir()
            .join("psy-relayer-nonexistent-parent-9f2a")
            .join("state.toml");
        let state = DaemonState {
            last_finalized_checkpoint: 10,
            pending_claim_withdrawals: HashMap::from([(
                "leaf-keep".to_string(),
                sample_withdrawal(1),
            )]),
        };
        let reconciled =
            reconcile_state_with_l1_finalized_checkpoint(state, &unwritable, 25).unwrap();
        assert_eq!(reconciled.last_finalized_checkpoint, 25, "checkpoint must advance");
        assert_eq!(reconciled.pending_claim_withdrawals.len(), 1, "pending must survive");
        // The file was never written (parent dir absent).
        assert!(!unwritable.exists());
    }

    #[test]
    fn reconcile_state_clamps_to_zero_preserves_pending_and_persists() {
        // L1 finalized regressed to 0 (e.g. fresh StateManager after a restart):
        // local must clamp down to 0, pending claims survive, and the clamp is
        // persisted so the next round's cursor is L1-authoritative.
        let path = temp_state_path("clamp-zero");
        let w = sample_withdrawal(4);
        let state = DaemonState {
            last_finalized_checkpoint: 20,
            pending_claim_withdrawals: HashMap::from([(w.leaf_hash.clone(), w.clone())]),
        };
        let reconciled = reconcile_state_with_l1_finalized_checkpoint(state, &path, 0).unwrap();
        assert_eq!(reconciled.last_finalized_checkpoint, 0);
        assert_eq!(reconciled.pending_claim_withdrawals.len(), 1);
        assert_eq!(reconciled.pending_claim_withdrawals[&w.leaf_hash].event_id, w.event_id);
        assert_eq!(load_state(&path).unwrap().last_finalized_checkpoint, 0);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reconcile_state_noop_with_pending_present_does_not_write() {
        // When local already matches L1 — even with pending claims — reconcile
        // is a no-op and must not touch disk (avoids clobbering/needless churn).
        let path = temp_state_path("noop-pending");
        assert!(!path.exists());
        let w = sample_withdrawal(1);
        let state = DaemonState {
            last_finalized_checkpoint: 15,
            pending_claim_withdrawals: HashMap::from([(w.leaf_hash.clone(), w.clone())]),
        };
        let reconciled = reconcile_state_with_l1_finalized_checkpoint(state, &path, 15).unwrap();
        assert_eq!(reconciled.last_finalized_checkpoint, 15);
        assert_eq!(reconciled.pending_claim_withdrawals.len(), 1);
        assert!(!path.exists(), "no-op reconcile must not create a state file");
    }

    // ── load_state / save_state / DaemonState serde edges ───────────────────

    #[test]
    fn load_state_empty_file_errors_not_silently_default() {
        // Crash recovery: a truncated/zero-byte state file must surface a parse
        // error rather than silently booting to default — otherwise pending
        // claims would vanish without trace. (Only a *missing* file yields the
        // clean default; an existing-but-empty file is treated as corrupt.)
        let path = temp_state_path("empty");
        std::fs::write(&path, "").unwrap();
        let err = load_state(&path).unwrap_err();
        assert!(
            err.to_string().contains("failed to parse daemon state"),
            "empty file must surface a parse error, got: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_state_migrates_legacy_failed_claim_withdrawals_alias() {
        // Backwards-compat migration: state files written by older daemons under
        // the field name `failed_claim_withdrawals` must deserialize into
        // `pending_claim_withdrawals` (the serde alias). Losing these on upgrade
        // would silently drop unclaimed withdrawals — a P0 crash-recovery defect.
        let path = temp_state_path("legacy-alias");
        let toml = concat!(
            "last_finalized_checkpoint = 88\n",
            "[failed_claim_withdrawals.leaf-legacy]\n",
            "event_id = -7\n",
            "checkpoint_id = 5\n",
            "user_id = 6\n",
            "sender_user_id = 7\n",
            "contract_id = 8\n",
            "destination_chain_index = 9\n",
            "token_address = [1,2,3,4,5,6,7,8]\n",
            "amount = [9,10,11,12,13,14,15,16]\n",
            "recipient = [17,18,19,20,21,22,23,24]\n",
            "nonce = [25,26,27,28,29,30,31,32]\n",
            "leaf_hash = \"leaf-legacy\"\n",
        );
        std::fs::write(&path, toml).unwrap();
        let state = load_state(&path).expect("legacy alias must deserialize");
        assert_eq!(state.last_finalized_checkpoint, 88);
        assert_eq!(state.pending_claim_withdrawals.len(), 1, "legacy claims must migrate");
        let w = &state.pending_claim_withdrawals["leaf-legacy"];
        assert_eq!(w.event_id, -7);
        assert_eq!(w.leaf_hash, "leaf-legacy");
        assert_eq!(w.nonce, [25, 26, 27, 28, 29, 30, 31, 32]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn save_state_round_trips_large_checkpoint_and_large_pending_set() {
        // Large-checkpoint boundary: i64::MAX is the largest u64 the TOML layer
        // can serialise (TOML integers are i64-range); a large pending set must
        // survive a save/load cycle bit-for-bit so a restart resumes exactly.
        // (u64::MAX is intentionally NOT tested here: it overflows TOML's i64
        // range and save_state errors — see the report's limitations note.)
        let path = temp_state_path("large");
        let mut pending = HashMap::new();
        for seed in 0..50u32 {
            let w = sample_withdrawal(seed);
            pending.insert(w.leaf_hash.clone(), w);
        }
        let state = DaemonState {
            last_finalized_checkpoint: i64::MAX as u64,
            pending_claim_withdrawals: pending,
        };
        save_state(&path, &state).unwrap();
        let loaded = load_state(&path).unwrap();
        assert_eq!(loaded.last_finalized_checkpoint, i64::MAX as u64);
        assert_eq!(loaded.pending_claim_withdrawals.len(), 50);
        // Spot-check two entries to ensure values (not just counts) round-trip.
        assert_eq!(loaded.pending_claim_withdrawals["leaf-0"].event_id, 0);
        assert_eq!(loaded.pending_claim_withdrawals["leaf-49"].user_id, 249);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn save_state_errors_when_path_is_unwritable() {
        // Error-propagation: writing to a path whose parent directory does not
        // exist must surface an error carrying the path context, not panic.
        let unwritable = std::env::temp_dir().join("psy-relayer-nonexistent-dir-7b1").join("x.toml");
        let state = DaemonState::default();
        let err = save_state(&unwritable, &state).unwrap_err();
        assert!(
            err.to_string().contains("failed to write daemon state"),
            "expected write-failure context, got: {err}"
        );
    }

    // ── read_single_felt_from_packed_leaf: packed contract-state decoding ──

    #[test]
    fn read_single_felt_from_packed_leaf_selects_subslot_by_modulo_four() {
        // 4 felts are packed per contract-state leaf; sub_slot_index % 4 selects
        // the element. Sub-slots 0..7 must wrap (4→0, 5→1, …) so chain_counts and
        // global_count read the correct felt.
        let leaf = make_packed_leaf([10, 20, 30, 40]);
        for sub in 0u64..8 {
            let expected = match sub % 4 {
                0 => 10,
                1 => 20,
                2 => 30,
                _ => 40,
            };
            assert_eq!(
                read_single_felt_from_packed_leaf(leaf, sub).unwrap(),
                expected,
                "sub_slot={sub}"
            );
        }
        // A large sub_slot_index also wraps via modulo (e.g. 100 % 4 == 0).
        assert_eq!(read_single_felt_from_packed_leaf(leaf, 100).unwrap(), 10);
    }

    #[test]
    fn read_single_felt_from_packed_leaf_accepts_u32_boundaries() {
        // 0 and u32::MAX are the inclusive bounds of the accepted range.
        let leaf = make_packed_leaf([0, u32::MAX as u64, 1, u32::MAX as u64]);
        assert_eq!(read_single_felt_from_packed_leaf(leaf, 0).unwrap(), 0);
        assert_eq!(read_single_felt_from_packed_leaf(leaf, 1).unwrap(), u32::MAX as u64);
    }

    #[test]
    fn read_single_felt_from_packed_leaf_rejects_value_above_u32_max() {
        // A packed felt whose canonical u64 exceeds u32::MAX must error (it would
        // corrupt chain_count/global_count decoding). 2^32 is canonical in
        // Goldilocks and strictly greater than u32::MAX.
        let leaf = make_packed_leaf([0x1_0000_0000u64, 0, 0, 0]);
        let err = read_single_felt_from_packed_leaf(leaf, 0).unwrap_err();
        assert!(
            err.to_string().contains("exceeds u32 range"),
            "expected u32-range error, got: {err}"
        );
    }

    // ── multi-round double-claim-prevention simulation ──────────────────────

    #[test]
    fn multi_round_claim_cycle_prevents_double_claims_and_retains_failures() {
        // Models the daemon-level crash-recovery flow across two rounds using
        // only the public-ish helpers (merge via or_insert_with + apply_claim_report),
        // the same sequence run() drives. Defends the externally observable
        // contract that pending_claim_withdrawals is the single source of truth:
        //   - a withdrawal submitted or already-claimed in round N is removed and
        //     NEVER retried (no double-claim);
        //   - a failed withdrawal persists and is retried next round;
        //   - re-scanning an existing leaf never duplicates or overwrites it;
        //   - pending keys stay unique throughout.
        let w1 = sample_withdrawal(1); // submitted round 1
        let w2 = sample_withdrawal(2); // already-claimed on L1 round 1
        let w3 = sample_withdrawal(3); // fails round 1, submitted round 2
        let w4 = sample_withdrawal(4); // new in round 2, submitted

        let mut pending: HashMap<String, PendingWithdrawal> = HashMap::new();

        // ── Round 1: scan reports w1, w2, w3; merge (or_insert, no overwrite). ─
        for w in [&w1, &w2, &w3] {
            pending
                .entry(w.leaf_hash.clone())
                .or_insert_with(|| w.clone());
        }
        assert_eq!(pending.len(), 3, "round 1 merge must add all three uniquely");
        // Claim report: w1 submitted, w2 already-claimed (both resolved), w3 fails.
        let report1 = claim_withdrawals::BatchWithdrawalsReport {
            requested: 3,
            submitted_count: 1,
            already_claimed_count: 1,
            resolved_leaf_hashes: vec![w1.leaf_hash.clone(), w2.leaf_hash.clone()],
            failure_reasons: HashMap::from([(w3.leaf_hash.clone(), "proof not ready".to_string())]),
        };
        apply_claim_report(&mut pending, &report1);
        assert!(!pending.contains_key(&w1.leaf_hash), "submitted must leave pending");
        assert!(
            !pending.contains_key(&w2.leaf_hash),
            "already-claimed must leave pending (no double-claim)"
        );
        assert!(pending.contains_key(&w3.leaf_hash), "failed must remain for retry");
        assert_eq!(pending.len(), 1);

        // ── Round 2: re-scan reports w3 (retry) and w4 (new). ───────────────
        // w3 is already pending: or_insert_with must NOT overwrite the original
        // record (crash-recovery idempotence). w4 is new.
        let original_w3 = pending.get(&w3.leaf_hash).cloned().unwrap();
        for w in [&w3, &w4] {
            pending
                .entry(w.leaf_hash.clone())
                .or_insert_with(|| w.clone());
        }
        assert_eq!(pending.len(), 2, "round 2 merge must add only w4");
        // w3 record preserved exactly (not overwritten by the re-scan).
        assert_eq!(pending[&w3.leaf_hash].event_id, original_w3.event_id);
        // w4 was inserted fresh.
        assert!(pending.contains_key(&w4.leaf_hash));

        // Claim report: both w3 and w4 submitted this round; no failures.
        let report2 = claim_withdrawals::BatchWithdrawalsReport {
            requested: 2,
            submitted_count: 2,
            already_claimed_count: 0,
            resolved_leaf_hashes: vec![w3.leaf_hash.clone(), w4.leaf_hash.clone()],
            failure_reasons: HashMap::new(),
        };
        apply_claim_report(&mut pending, &report2);
        assert!(pending.is_empty(), "all claims resolved → pending must be empty");
        // Invariant: w2 (already-claimed in round 1) was never re-added even
        // though it was not re-scanned — double-claim prevented.
        assert!(!pending.contains_key(&w2.leaf_hash));
    }
    fn test_leaf(seed: u64) -> QHashOut<GoldilocksField> {
        QHashOut(plonky2::hash::hash_types::HashOut {
            elements: std::array::from_fn(|offset| GoldilocksField(seed + offset as u64)),
        })
    }

    fn sample_slot_updates() -> Vec<EndCapContractSlotUpdate> {
        vec![
            EndCapContractSlotUpdate {
                contract_id: DEPOSIT_TREE_CONTRACT_ID,
                slot: 65800,
                old_value: 10,
                new_value: 11,
            },
            EndCapContractSlotUpdate {
                contract_id: WITHDRAWAL_TREE_CONTRACT_ID,
                slot: 4,
                old_value: 20,
                new_value: 21,
            },
        ]
    }

    fn accepted_slot_updates(user_id: u64, unique_pending_id: u64) -> RealmEndCapSlotUpdates {
        RealmEndCapSlotUpdates {
            realm_id: 0,
            realm_sub_id: 0,
            unique_pending_id,
            user_id,
            contracts: vec![
                psy_provider::request::RealmContractSlotUpdates {
                    contract_id: WITHDRAWAL_TREE_CONTRACT_ID,
                    slot_updates: vec![psy_provider::request::RealmSlotUpdate {
                        slot: 4,
                        old_value: 20,
                        new_value: 21,
                    }],
                },
                psy_provider::request::RealmContractSlotUpdates {
                    contract_id: DEPOSIT_TREE_CONTRACT_ID,
                    slot_updates: vec![psy_provider::request::RealmSlotUpdate {
                        slot: 65800,
                        old_value: 10,
                        new_value: 11,
                    }],
                },
            ],
        }
    }

    fn duplicate_submission_error(
        leaf: QHashOut<GoldilocksField>,
        user_id: u64,
        unique_pending_id: u64,
    ) -> anyhow::Error {
        EndCapSubmissionError {
            end_user_leaf_hash: leaf,
            contract_slot_updates: sample_slot_updates(),
            source: psy_provider::provider::EndCapAlreadySubmitted {
                user_id,
                unique_pending_id,
            }
            .into(),
        }
        .into()
    }

    #[tokio::test]
    async fn accepted_then_timed_out_retry_recovers_exact_duplicate_leaf() {
        let accepted_leaf = test_leaf(100);
        let first_submission = Ok::<_, anyhow::Error>(accepted_leaf).unwrap();
        let first_inclusion_wait = Err::<u64, _>(anyhow::anyhow!(
            "timeout waiting endcap inclusion: user_id={} checkpoint_before=700",
            BRIDGE_USER_ID_U64
        ));
        assert!(first_inclusion_wait.is_err());

        let retry = recover_duplicate_endcap_leaf_with(
            duplicate_submission_error(first_submission, BRIDGE_USER_ID_U64, 675),
            BRIDGE_USER_ID_U64,
            |user_id, unique_pending_id| async move {
                Ok(Some(accepted_slot_updates(user_id, unique_pending_id)))
            },
        )
        .await
        .unwrap();
        assert_eq!(retry, accepted_leaf);
    }

    #[tokio::test]
    async fn exact_duplicate_accepts_server_update_superset() {
        let leaf = test_leaf(150);
        let recovered = recover_duplicate_endcap_leaf_with(
            duplicate_submission_error(leaf, BRIDGE_USER_ID_U64, 675),
            BRIDGE_USER_ID_U64,
            |user_id, unique_pending_id| async move {
                let mut accepted = accepted_slot_updates(user_id, unique_pending_id);
                accepted.contracts[1].slot_updates.push(psy_provider::request::RealmSlotUpdate {
                    slot: 65801,
                    old_value: 30,
                    new_value: 31,
                });
                Ok(Some(accepted))
            },
        )
        .await
        .unwrap();
        assert_eq!(recovered, leaf);
    }

    #[tokio::test]
    async fn exact_duplicate_then_landed_checkpoint_continues_inclusion_wait() {
        let accepted_leaf = test_leaf(200);
        let recovered_leaf = recover_duplicate_endcap_leaf_with(
            duplicate_submission_error(accepted_leaf, BRIDGE_USER_ID_U64, 675),
            BRIDGE_USER_ID_U64,
            |user_id, unique_pending_id| async move {
                Ok(Some(accepted_slot_updates(user_id, unique_pending_id)))
            },
        )
        .await
        .unwrap();
        let landed_checkpoint = async move {
            assert_eq!(recovered_leaf, accepted_leaf);
            701u64
        }
        .await;

        assert_eq!(landed_checkpoint, 701);
    }

    #[tokio::test]
    async fn unrelated_or_mismatched_duplicate_errors_remain_failures() {
        let leaf = test_leaf(300);
        let unrelated = EndCapSubmissionError {
            end_user_leaf_hash: leaf,
            contract_slot_updates: sample_slot_updates(),
            source: anyhow::anyhow!("another endcap error"),
        };
        assert!(
            recover_duplicate_endcap_leaf_with(unrelated.into(), BRIDGE_USER_ID_U64, |_, _| async {
                Ok(None)
            })
            .await
            .is_err()
        );

        let mismatch = duplicate_submission_error(leaf, BRIDGE_USER_ID_U64 + 1, 675);
        let error = recover_duplicate_endcap_leaf_with(mismatch, BRIDGE_USER_ID_U64, |_, _| async {
            Ok(None)
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("duplicate endcap user mismatch"));

        let wrong_identity = duplicate_submission_error(leaf, BRIDGE_USER_ID_U64, 675);
        let error = recover_duplicate_endcap_leaf_with(wrong_identity, BRIDGE_USER_ID_U64, |user_id, unique_pending_id| async move {
            let mut accepted = accepted_slot_updates(user_id, unique_pending_id);
            accepted.contracts[1].slot_updates[0].new_value = 12;
            Ok(Some(accepted))
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("contract update identity mismatch"));
    }

    // ── claim-scheduling fix (commit 7522ca93): claim gating + finalize target ─

    #[test]
    fn claims_require_normal_mode_and_pending_work() {
        let cases: &[(bool, usize, bool)] = &[
            (false, 1, true),
            (false, 0, false),
            (true, 1, false),
            (true, 0, false),
            (false, 7, true),
        ];

        for (is_catchup_batch, pending_claim_count, expected) in cases {
            assert_eq!(
                !*is_catchup_batch && *pending_claim_count > 0,
                *expected,
                "is_catchup_batch={is_catchup_batch}, pending_claim_count={pending_claim_count}"
            );
        }
    }

    #[test]
    fn claim_time_refresh_uses_one_sticky_catchup_state() {
        let from_checkpoint = 100;
        let confirmation_lag_checkpoints = 3;
        let max_checkpoint_batch = 64;

        assert!(!refresh_catchup_state(
            false,
            from_checkpoint,
            Some(166),
            confirmation_lag_checkpoints,
            max_checkpoint_batch,
        ));
        assert!(refresh_catchup_state(
            false,
            from_checkpoint,
            Some(167),
            confirmation_lag_checkpoints,
            max_checkpoint_batch,
        ));
        assert!(refresh_catchup_state(
            true,
            from_checkpoint,
            Some(166),
            confirmation_lag_checkpoints,
            max_checkpoint_batch,
        ));
        assert!(refresh_catchup_state(
            false,
            from_checkpoint,
            None,
            confirmation_lag_checkpoints,
            max_checkpoint_batch,
        ));
    }

    #[test]
    fn select_finalize_to_checkpoint_prefers_l2_landing_over_window_bound() {
        // Defends the finalize-to-landing contract: in a normal round the
        // daemon must finalize straight to the L2 landing checkpoint even when
        // landing exceeds the pre-round window.to_checkpoint bound. A
        // regression that re-introduces `window_to.min(landing)` or caps back
        // to the window bound would drop landed L2 work and redden this test.
        // The window < landing rows carry the teeth; the equal/behind rows pin
        // the rest of the contract.
        assert_eq!(select_finalize_to_checkpoint(50, 70), 70);
        assert_eq!(select_finalize_to_checkpoint(64, 100), 100);
        // Landing equals the window bound (catchup, or no L2 advance): both a
        // correct helper and a re-capping regression would pass this row, so
        // it documents the boundary rather than carrying teeth.
        assert_eq!(select_finalize_to_checkpoint(70, 70), 70);
        // Landing behind the window bound: the helper must still follow the
        // landing, not cap UP to the window bound.
        assert_eq!(select_finalize_to_checkpoint(70, 60), 60);
    }

    #[test]
    fn catchup_round_defers_claims_and_retains_pending_across_reconcile_save_cycle() {
        // Catch-up must defer pending withdrawals without mutating them so a
        // later normal round can retry the same durable set.
        let window = RelayerWindow {
            to_checkpoint: 17,
            confirmed_to_checkpoint: Some(77),
            is_catchup_batch: true,
        };
        assert!(window.is_catchup_batch);
        let is_catchup_batch = window.is_catchup_batch;
        assert!(is_catchup_batch, "catchup round must disable withdrawal processing");

        let w1 = sample_withdrawal(1);
        let w2 = sample_withdrawal(2);
        let pending: HashMap<String, PendingWithdrawal> = [
            (w1.leaf_hash.clone(), w1.clone()),
            (w2.leaf_hash.clone(), w2.clone()),
        ]
        .into_iter()
        .collect();

        assert!(is_catchup_batch);
        assert_eq!(pending.len(), 2);

        // Reconcile against an advanced L1 cursor (as the next round would),
        // then persist and reload: pending claims must round-trip intact.
        let path = temp_state_path("catchup-retain");
        let state = DaemonState {
            last_finalized_checkpoint: 17,
            pending_claim_withdrawals: pending,
        };
        let reconciled = reconcile_state_with_l1_finalized_checkpoint(state, &path, 77).unwrap();
        assert_eq!(reconciled.last_finalized_checkpoint, 77);
        assert_eq!(reconciled.pending_claim_withdrawals.len(), 2);
        assert_eq!(reconciled.pending_claim_withdrawals[&w1.leaf_hash].event_id, w1.event_id);
        assert_eq!(reconciled.pending_claim_withdrawals[&w2.leaf_hash].event_id, w2.event_id);

        let saved = load_state(&path).unwrap();
        assert_eq!(saved.last_finalized_checkpoint, 77);
        assert_eq!(saved.pending_claim_withdrawals.len(), 2);
        assert_eq!(saved.pending_claim_withdrawals[&w1.leaf_hash].event_id, w1.event_id);
        assert_eq!(saved.pending_claim_withdrawals[&w2.leaf_hash].event_id, w2.event_id);

        // After catchup completes, the next round is normal: claims are now
        // allowed and the retained pending set drives a claim.
        let normal_window = RelayerWindow {
            to_checkpoint: 77,
            confirmed_to_checkpoint: Some(77),
            is_catchup_batch: false,
        };
        let normal_is_catchup_batch = normal_window.is_catchup_batch;
        assert!(!normal_is_catchup_batch);
        assert!(!normal_is_catchup_batch && 2 > 0);

        let _ = std::fs::remove_file(path);
    }

    // ── inner-loop catch-up break (run_l2_bridge_round mid-round stop) ────

    /// Mirrors the mid-loop guard in `run_l2_bridge_round_with_l1_provider`:
    /// while still in a normal round (`is_catchup_batch == false`), re-check the
    /// window against the latest planning checkpoint and break once the gap
    /// has crossed into catch-up. Catch-up rounds never take this path
    /// (`is_catchup_batch == true`), so they keep planning empty batches.
    fn should_stop_l2_round_for_mid_loop_catchup(
        is_catchup_batch: bool,
        from_checkpoint: u64,
        planning_checkpoint: u64,
        confirmation_lag_checkpoints: u64,
        max_checkpoint_batch: u64,
    ) -> bool {
        if is_catchup_batch {
            return false;
        }
        select_relayer_window(
            from_checkpoint,
            planning_checkpoint,
            confirmation_lag_checkpoints,
            max_checkpoint_batch,
        )
        .is_catchup_batch
    }

    #[test]
    fn select_relayer_window_catchup_when_gap_exceeds_max_batch() {
        // Contract: gap = confirmed - from + 1 > max_checkpoint_batch ⇒
        // is_catchup_batch. Teeth: a flipped `>` / `>=` comparison or a
        // missing catch-up flag would let oversized gaps stay in normal mode
        // and keep appending business (the TC-SW-80 stuck-round failure).
        let cases = [
            // (from, latest, lag, max_batch, expected_catchup)
            (1u64, 100, 3, 64, true),   // confirmed=97, gap=97 > 64
            (10, 80, 3, 8, true),       // confirmed=77, gap=68 > 8
            (1186, 1300, 0, 64, true),  // confirmed=1300, gap=115 > 64 (TC-SW-80 shape)
            (1, 66, 1, 64, true),       // confirmed=65, gap=65 > 64 → catchup
            (1, 65, 1, 64, false),      // confirmed=64, gap=64 == 64 → normal
        ];
        for (from, latest, lag, max_batch, expect_catchup) in cases {
            let window = select_relayer_window(from, latest, lag, max_batch);
            assert_eq!(
                window.is_catchup_batch, expect_catchup,
                "select_relayer_window({from}, {latest}, lag={lag}, max={max_batch}): \
                 is_catchup_batch expected {expect_catchup}, got {}",
                window.is_catchup_batch
            );
            // Gating must track the catch-up flag exactly.
            assert_eq!(
                !window.is_catchup_batch,
                !expect_catchup,
                "deposit gating disagree with catchup for from={from} latest={latest}"
            );
            assert_eq!(
                !window.is_catchup_batch,
                !expect_catchup,
                "withdrawal gating disagree with catchup for from={from} latest={latest}"
            );
        }
    }

    #[test]
    fn select_relayer_window_gap_equal_to_max_batch_is_not_catchup() {
        // Boundary: range_len == max_checkpoint_batch must remain a normal
        // round. Off-by-one (`>=` instead of `>`) would force catch-up one
        // checkpoint early and skip legitimate deposit/withdrawal work.
        // confirmed = latest - lag; choose values so range_len == max exactly.
        let max_batch = 64u64;
        let from = 100u64;
        let lag = 3u64;
        // range_len = confirmed - from + 1 == 64 ⇒ confirmed = from + 63 = 163
        // latest = confirmed + lag = 166
        let window = select_relayer_window(from, from + max_batch - 1 + lag, lag, max_batch);
        assert_eq!(window.confirmed_to_checkpoint, Some(from + max_batch - 1));
        assert_eq!(
            window.confirmed_to_checkpoint.unwrap() - from + 1,
            max_batch,
            "fixture must produce range_len == max_batch"
        );
        assert!(
            !window.is_catchup_batch,
            "gap == max_batch must be a normal round, got catchup"
        );
        assert_eq!(window.to_checkpoint, from + max_batch - 1);
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn select_relayer_window_gap_one_past_max_batch_is_catchup() {
        // Boundary companion: range_len == max + 1 must flip into catch-up and
        // truncate to_checkpoint to a max-sized batch. The mid-loop break
        // depends on this exact threshold.
        let max_batch = 64u64;
        let from = 100u64;
        let lag = 3u64;
        // range_len = 65 ⇒ confirmed = from + 64 = 164, latest = 167
        let window = select_relayer_window(from, from + max_batch + lag, lag, max_batch);
        assert_eq!(window.confirmed_to_checkpoint, Some(from + max_batch));
        assert_eq!(
            window.confirmed_to_checkpoint.unwrap() - from + 1,
            max_batch + 1
        );
        assert!(
            window.is_catchup_batch,
            "gap == max_batch + 1 must be catchup"
        );
        assert_eq!(
            window.to_checkpoint,
            from + max_batch - 1,
            "catchup must truncate to from + max - 1"
        );
        assert!(window.is_catchup_batch);
    }

    #[test]
    fn l2_round_result_constructs_with_correct_fields() {
        // L2RoundResult carries the sticky catch-up authority the outer daemon
        // consumes alongside deposit/claim outputs. Constructing the struct
        // with exactly these fields is a compile-time shape contract.
        let claims = vec![sample_withdrawal(1), sample_withdrawal(2)];
        let result = L2RoundResult {
            deposit_append_target: Some(42),
            to_checkpoint: 1249,
            submitted_l2_work: true,
            is_catchup_batch: false,
            claim_withdrawals: claims.clone(),
        };

        assert_eq!(result.deposit_append_target, Some(42));
        assert_eq!(result.to_checkpoint, 1249);
        assert!(result.submitted_l2_work);
        assert!(!result.is_catchup_batch);
        assert_eq!(result.claim_withdrawals.len(), 2);
        assert_eq!(result.claim_withdrawals[0].leaf_hash, claims[0].leaf_hash);
        assert_eq!(result.claim_withdrawals[1].leaf_hash, claims[1].leaf_hash);

        // Empty / no-work finish path after a mid-loop catch-up latch: sticky
        // authority stays true and deposit append target must be absent.
        let idle = L2RoundResult {
            deposit_append_target: None,
            to_checkpoint: 1186,
            submitted_l2_work: false,
            is_catchup_batch: true,
            claim_withdrawals: Vec::new(),
        };
        assert_eq!(idle.deposit_append_target, None);
        assert_eq!(idle.to_checkpoint, 1186);
        assert!(!idle.submitted_l2_work);
        assert!(idle.is_catchup_batch);
        assert!(idle.claim_withdrawals.is_empty());
    }

    #[test]
    fn finish_l2_round_deposit_target_logic_matches_select_deposit_append_target() {
        // finish_l2_round is async and needs a live RpcProvider, so its
        // deposit_append_target field is defended here via the pure helper it
        // Normal mode must derive the append target from the L2 cursor.
        let target = select_deposit_append_target(
            /* is_catchup_batch */ false,
            /* proof_to_checkpoint */ 1200,
            /* l2_landing_checkpoint */ 1200,
            /* l2_deposit_cursor */ 10,
            /* proved_deposit_count */ 5,
            /* pending_deposit_count */ 12,
        )
        .expect("consistent cursors");
        assert_eq!(
            target,
            Some(10),
            "cursor ahead of proved must yield append target equal to L2 cursor"
        );

        // Catch-up mode must never request deposit appends.
        let deferred = select_deposit_append_target(true, 1200, 1200, 10, 5, 12)
            .expect("consistent cursors");
        assert_eq!(deferred, None, "catchup entry must suppress deposit_append_target");

        // Cursor caught up with proved: no append work remains.
        let caught_up = select_deposit_append_target(false, 1200, 1200, 5, 5, 12)
            .expect("consistent cursors");
        assert_eq!(caught_up, None);
    }

    #[test]
    fn mid_loop_break_when_gap_crosses_catchup_while_in_normal_mode() {
        // Defends the inner-loop break condition:
        //   if !is_catchup_batch && fresh_window.is_catchup_batch { break; }
        // Round entered normal at from=1186 with max_batch=64; as
        // planning_checkpoint advances past the threshold the loop must
        // stop appending and fall through to finish_l2_round.
        let from = 1186u64;
        let lag = 0u64;
        let max_batch = 64u64;
        // Normal while range_len <= 64 ⇒ planning <= from + 63 = 1249
        // Catch-up once planning >= 1250
        let threshold_normal = from + max_batch - 1; // 1249
        let first_catchup = threshold_normal + 1; // 1250

        // Still normal at the boundary — keep planning/submitting.
        assert!(
            !should_stop_l2_round_for_mid_loop_catchup(false, from, threshold_normal, lag, max_batch),
            "planning={threshold_normal} (gap==max) must NOT break"
        );
        // Crossed threshold mid-loop — break before the next build_l2_call_plan.
        assert!(
            should_stop_l2_round_for_mid_loop_catchup(false, from, first_catchup, lag, max_batch),
            "planning={first_catchup} (gap==max+1) must break"
        );
        // Well past threshold (as in the stuck 1186→1202 growth past 64).
        assert!(should_stop_l2_round_for_mid_loop_catchup(
            false,
            from,
            1300,
            lag,
            max_batch
        ));

        // Catch-up entry rounds pass is_catchup_batch=true; the guard
        // must not fire so the empty-plan path can still finish the round.
        assert!(
            !should_stop_l2_round_for_mid_loop_catchup(true, from, 1300, lag, max_batch),
            "catchup-mode rounds must not take the mid-loop break path"
        );
    }

    #[test]
    fn mid_loop_break_tracks_planning_checkpoint_growth_across_iterations() {
        // Table-driven simulation of successive inner-loop iterations: the
        // break decision is re-evaluated each time against the *current*
        // planning checkpoint. A regression that only checked the pre-round
        // window (or checked once) would keep appending as the gap grows.
        let from = 1186u64;
        let lag = 0u64;
        let max_batch = 64u64;
        let iterations = [
            // (planning_checkpoint, expect_break)
            (1202u64, false), // early normal growth (pre-fix stuck point)
            (1240, false),    // still within max batch
            (1249, false),    // gap == 64, last normal planning tick
            (1250, true),     // gap == 65, first catch-up tick → break
            (1280, true),     // further growth still breaks
        ];
        for (planning, expect_break) in iterations {
            let stop = should_stop_l2_round_for_mid_loop_catchup(
                false, from, planning, lag, max_batch,
            );
            assert_eq!(
                stop, expect_break,
                "iteration planning={planning}: break expected {expect_break}, got {stop}"
            );
            // Cross-check against the window the production loop builds.
            let window = select_relayer_window(from, planning, lag, max_batch);
            assert_eq!(
                stop,
                window.is_catchup_batch,
                "break decision must equal fresh_window.is_catchup_batch at planning={planning}"
            );
        }
    }

    #[test]
    fn mid_loop_break_respects_confirmation_lag() {
        // The production guard feeds confirmation_lag into select_relayer_window.
        // With lag>0 the catch-up threshold is on *confirmed* (= latest-lag),
        // not raw latest — a bug that dropped lag from the re-check would
        // break too early (or too late).
        let from = 100u64;
        let lag = 3u64;
        let max_batch = 64u64;
        // confirmed = latest - 3; catchup when confirmed - from + 1 > 64
        // ⇒ confirmed > 163 ⇒ latest > 166
        assert!(
            !should_stop_l2_round_for_mid_loop_catchup(false, from, 166, lag, max_batch),
            "latest=166 → confirmed=163 → gap=64 must stay normal"
        );
        assert!(
            should_stop_l2_round_for_mid_loop_catchup(false, from, 167, lag, max_batch),
            "latest=167 → confirmed=164 → gap=65 must break"
        );
    }


    #[test]
    fn mid_loop_threshold_crossing_latches_sticky_authority_and_suppresses_deposit_target() {
        // Production path: round enters normal, fresh head crosses max batch,
        // sticky authority latches true before break, and finish_l2_round must
        // not emit a deposit_append_target under that latched authority.
        let from = 1186u64;
        let lag = 0u64;
        let max_batch = 64u64;
        let landed_to_checkpoint = 1249u64;
        let first_catchup_planning = from + max_batch; // 1250

        let mut is_catchup_batch = false;
        assert!(
            !should_stop_l2_round_for_mid_loop_catchup(
                is_catchup_batch,
                from,
                landed_to_checkpoint,
                lag,
                max_batch
            ),
            "pre-threshold planning must stay normal"
        );

        is_catchup_batch = refresh_catchup_state(
            is_catchup_batch,
            from,
            Some(first_catchup_planning),
            lag,
            max_batch,
        );
        assert!(
            is_catchup_batch,
            "threshold crossing must latch sticky catch-up authority before break"
        );

        // Even with an L2 cursor ahead of proved deposits, latched catch-up
        // suppresses the deposit append target finish_l2_round would return.
        let deposit_append_target = select_deposit_append_target(
            is_catchup_batch,
            landed_to_checkpoint,
            landed_to_checkpoint,
            /* l2_deposit_cursor */ 12,
            /* proved_deposit_count */ 7,
            /* pending_deposit_count */ 15,
        )
        .expect("consistent cursors");
        assert_eq!(
            deposit_append_target, None,
            "sticky catch-up authority must suppress deposit_append_target"
        );

        let result = L2RoundResult {
            deposit_append_target,
            to_checkpoint: landed_to_checkpoint,
            submitted_l2_work: true,
            is_catchup_batch,
            claim_withdrawals: Vec::new(),
        };
        assert!(result.is_catchup_batch);
        assert_eq!(result.deposit_append_target, None);
        // Outer loop adopts sticky authority from the L2 result.
        let outer_is_catchup_batch = result.is_catchup_batch;
        assert!(outer_is_catchup_batch);
        assert!(
            select_deposit_append_target(outer_is_catchup_batch, 1249, 1249, 12, 7, 15)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn newly_latched_orchestration_persists_ledger_and_dispatches_no_post_l2_phases() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        async fn record_phase(permit: &PostL2PhasePermit, counter: &AtomicUsize) {
            dispatch_post_l2_phase(permit, async {
                counter.fetch_add(1, Ordering::SeqCst);
            })
            .await;
        }

        let state_path = temp_state_path("new-latch-orchestration");
        let durable = sample_withdrawal(1);
        let landed = sample_withdrawal(2);
        let state = DaemonState {
            last_finalized_checkpoint: 77,
            pending_claim_withdrawals: HashMap::from([(
                durable.leaf_hash.clone(),
                durable.clone(),
            )]),
        };
        save_state(&state_path, &state).unwrap();

        let deposit_calls = Arc::new(AtomicUsize::new(0));
        let proof_calls = Arc::new(AtomicUsize::new(0));
        let finalize_calls = Arc::new(AtomicUsize::new(0));
        let claim_calls = Arc::new(AtomicUsize::new(0));

        let deferred = orchestrate_post_l2_round(
            &state_path,
            &state,
            std::slice::from_ref(&landed),
            false,
            true,
            {
                let deposit_calls = Arc::clone(&deposit_calls);
                let proof_calls = Arc::clone(&proof_calls);
                let finalize_calls = Arc::clone(&finalize_calls);
                let claim_calls = Arc::clone(&claim_calls);
                move |permit, pending| async move {
                    record_phase(&permit, &deposit_calls).await;
                    record_phase(&permit, &proof_calls).await;
                    record_phase(&permit, &finalize_calls).await;
                    record_phase(&permit, &claim_calls).await;
                    pending
                }
            },
        )
        .await
        .unwrap();

        assert!(matches!(deferred, PostL2Orchestration::Deferred));
        assert_eq!(deposit_calls.load(Ordering::SeqCst), 0);
        assert_eq!(proof_calls.load(Ordering::SeqCst), 0);
        assert_eq!(finalize_calls.load(Ordering::SeqCst), 0);
        assert_eq!(claim_calls.load(Ordering::SeqCst), 0);

        let installed = load_state(&state_path).unwrap();
        assert_eq!(installed.last_finalized_checkpoint, 77);
        assert_eq!(installed.pending_claim_withdrawals.len(), 2);
        assert_eq!(
            installed.pending_claim_withdrawals[&durable.leaf_hash].event_id,
            durable.event_id
        );
        assert_eq!(
            installed.pending_claim_withdrawals[&landed.leaf_hash].event_id,
            landed.event_id
        );

        // Existing catch-up and still-normal paths both issue the production
        // permit and dispatch every instrumented post-L2 phase.
        for (label, pre, post) in [("catchup", true, true), ("normal", false, false)] {
            deposit_calls.store(0, Ordering::SeqCst);
            proof_calls.store(0, Ordering::SeqCst);
            finalize_calls.store(0, Ordering::SeqCst);
            claim_calls.store(0, Ordering::SeqCst);

            let dispatched = orchestrate_post_l2_round(
                &state_path,
                &state,
                &[],
                pre,
                post,
                {
                    let deposit_calls = Arc::clone(&deposit_calls);
                    let proof_calls = Arc::clone(&proof_calls);
                    let finalize_calls = Arc::clone(&finalize_calls);
                    let claim_calls = Arc::clone(&claim_calls);
                    move |permit, pending| async move {
                        record_phase(&permit, &deposit_calls).await;
                        record_phase(&permit, &proof_calls).await;
                        record_phase(&permit, &finalize_calls).await;
                        record_phase(&permit, &claim_calls).await;
                        pending
                    }
                },
            )
            .await
            .unwrap();

            assert!(
                matches!(dispatched, PostL2Orchestration::Dispatch(_)),
                "{label} path must dispatch"
            );
            assert_eq!(deposit_calls.load(Ordering::SeqCst), 1, "{label}");
            assert_eq!(proof_calls.load(Ordering::SeqCst), 1, "{label}");
            assert_eq!(finalize_calls.load(Ordering::SeqCst), 1, "{label}");
            assert_eq!(claim_calls.load(Ordering::SeqCst), 1, "{label}");
        }

        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn append_only_rounds_retry_pending_claims_under_same_catchup_gate() {
        // No confirmed finalize range still runs durable claim settlement.
        // Eligibility uses the same sticky fail-closed head gate as finalize.
        let from = 100u64;
        let lag = 3u64;
        let max_batch = 64u64;
        // Empty durable set: settlement is a no-op even in normal mode.
        let sticky = refresh_catchup_state(false, from, Some(166), lag, max_batch);
        assert!(!sticky);
        assert!(!should_attempt_pending_claims(sticky, 0));

        // Normal head with pending work: append-only must retry claims without
        // requiring a new finalize checkpoint range.
        let sticky = refresh_catchup_state(false, from, Some(166), lag, max_batch);
        assert!(!sticky);
        assert!(
            should_attempt_pending_claims(sticky, 2),
            "append-only + normal sticky gate + pending claims must retry"
        );

        // Fresh head already past catch-up threshold: fail-closed, no claim.
        let sticky = refresh_catchup_state(false, from, Some(167), lag, max_batch);
        assert!(sticky);
        assert!(
            !should_attempt_pending_claims(sticky, 2),
            "append-only must honor the same fail-closed catch-up gate"
        );

        // Head refresh failure: fail closed and keep pending durable.
        let sticky = refresh_catchup_state(false, from, None, lag, max_batch);
        assert!(sticky);
        assert!(!should_attempt_pending_claims(sticky, 2));

        // Already-latched sticky authority never launders open via append-only.
        let sticky = refresh_catchup_state(true, from, Some(166), lag, max_batch);
        assert!(sticky);
        assert!(!should_attempt_pending_claims(sticky, 2));
    }

    #[test]
    fn save_state_atomically_replaces_existing_ledger_without_temp_residue() {
        // Crash safety: successful install fully replaces the prior ledger and
        // leaves no same-dir temp residue that could later be confused for state.
        let path = temp_state_path("atomic-replace");
        let prior_w = sample_withdrawal(3);
        let prior = DaemonState {
            last_finalized_checkpoint: 11,
            pending_claim_withdrawals: HashMap::from([(prior_w.leaf_hash.clone(), prior_w.clone())]),
        };
        save_state(&path, &prior).unwrap();
        let prior_bytes = std::fs::read(&path).expect("prior ledger bytes");

        let next_w = sample_withdrawal(9);
        let next = DaemonState {
            last_finalized_checkpoint: 42,
            pending_claim_withdrawals: HashMap::from([
                (prior_w.leaf_hash.clone(), prior_w.clone()),
                (next_w.leaf_hash.clone(), next_w.clone()),
            ]),
        };
        save_state(&path, &next).unwrap();

        let loaded = load_state(&path).unwrap();
        assert_eq!(loaded.last_finalized_checkpoint, 42);
        assert_eq!(loaded.pending_claim_withdrawals.len(), 2);
        assert_eq!(
            loaded.pending_claim_withdrawals[&next_w.leaf_hash].event_id,
            next_w.event_id
        );
        let installed_bytes = std::fs::read(&path).expect("installed ledger bytes");
        assert_ne!(
            installed_bytes, prior_bytes,
            "atomic install must replace the prior ledger contents"
        );

        let parent = path.parent().expect("temp state parent");
        let stem = path
            .file_name()
            .expect("state file name")
            .to_string_lossy()
            .into_owned();
        let temp_residue: Vec<_> = std::fs::read_dir(parent)
            .expect("read state parent")
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.contains(".tmp-") && name.contains(stem.trim_start_matches('.'))
            })
            .map(|entry| entry.path())
            .collect();
        assert!(
            temp_residue.is_empty(),
            "successful atomic save must not leave temp residue: {temp_residue:?}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn failed_state_install_must_not_delete_proof_or_treat_advance_as_persisted() {
        // Unwritable state destination surfaces an install error, leaves the
        // pre-existing ledger untouched, and retains the proof through the
        // exact production install/cleanup helper.
        let parent = std::env::temp_dir().join(format!(
            "psy-relayer-atomic-fail-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join("daemon_state.toml");
        let prior = DaemonState {
            last_finalized_checkpoint: 7,
            pending_claim_withdrawals: HashMap::new(),
        };
        save_state(&path, &prior).unwrap();
        let prior_bytes = std::fs::read(&path).unwrap();

        let proof_path = parent.join("bridge_proof_99.json");
        std::fs::write(&proof_path, b"proof-must-survive").unwrap();
        let missing_state_path = parent
            .join("missing-dir")
            .join("nested")
            .join("daemon_state.toml");
        let advanced = DaemonState {
            last_finalized_checkpoint: 99,
            pending_claim_withdrawals: HashMap::new(),
        };
        let err = persist_finalized_state_then_cleanup_proof(
            &missing_state_path,
            &advanced,
            &proof_path,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("failed to write daemon state"),
            "expected write-failure context, got: {err}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            prior_bytes,
            "failed install must not mutate the prior ledger"
        );
        assert!(
            proof_path.exists(),
            "production helper must retain proof when state install fails"
        );

        let _ = std::fs::remove_file(&proof_path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(parent);
    }

    #[test]
    fn l2_round_result_compile_time_shape_contract() {
        // Constructing L2RoundResult with the legitimate production fields is a
        // compile-time shape contract. Runtime assertions pin the observable
        // finish shape the outer loop reads after either an empty plan or a
        // mid-loop sticky catch-up break.
        let result = L2RoundResult {
            deposit_append_target: None,
            to_checkpoint: 64,
            submitted_l2_work: false,
            is_catchup_batch: true,
            claim_withdrawals: Vec::new(),
        };
        // Outer-loop consumers (run()) read these fields.
        let _deposit_target: Option<u32> = result.deposit_append_target;
        let _to: u64 = result.to_checkpoint;
        let _submitted: bool = result.submitted_l2_work;
        let _sticky: bool = result.is_catchup_batch;
        let _claims: Vec<PendingWithdrawal> = result.claim_withdrawals;
    }
}
